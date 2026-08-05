"""Frozen DM-014 species registry, compatibility, preview, and application.

Species is lineage evidence.  Nothing in this module grants being identity,
membership, memory, routing, disclosure, birth, or body authority.
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
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import (
    CanonicalError,
    b64url,
    canonical_bytes,
    digest,
    domain_bytes,
    unb64url,
)
from .identity import ed25519_public, key_id
from .species_runner import (
    RUNNER_VERSION,
    DeterministicWasiRunner,
    ResourceProfile,
    SpeciesRunnerError,
)

MAX_SAFE_INTEGER: Final = 2**53 - 1
MAX_ARTIFACT_BYTES: Final = 262_144
MAX_CONTENT_BYTES: Final = 67_108_864
MAX_KEYS: Final = 32
MAX_SIGNATURES: Final = 128
MAX_SMALL_COLLECTION: Final = 64
MAX_EVIDENCE_ROWS: Final = 4096
MAX_INCOMING_PAGE: Final = 64
MAX_POSITION_PAGE: Final = 256
MAX_BUNDLE_DEPENDENCY_DEPTH: Final = 32
MAX_BUNDLE_DEPENDENCY_NODES: Final = 4096
MAX_BUNDLE_CLOSURE_BYTES: Final = 536_870_912
BUSY_TIMEOUT_MS: Final = 30_000

ARTIFACT_SCHEMA: Final = "daimon-species-artifact/v0"
GENESIS_SCHEMA: Final = "daimon-species-genesis/v0"
RELEASE_SCHEMA: Final = "daimon-species-release/v0"
GENESIS_DOMAIN: Final = "daimon/species-genesis/v0"
RELEASE_DOMAIN: Final = "daimon/species-release/v0"
SPECIES_ID_DOMAIN: Final = "daimon/species-id/v0"
INCOMING_SCHEMA: Final = "daimon-species-incoming-result/v0"
APPLICATION_SCHEMA: Final = "daimon-species-release-application/v0"
APPLICATION_EVENT_KIND: Final = "matrix/species-release-application"

_B64_32 = re.compile(r"^[A-Za-z0-9_-]{43}$")
_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")
_SPECIES_ID = re.compile(r"^dm:species:v0:[A-Za-z0-9_-]{43}$")
_CONTENT_ID = re.compile(r"^dm:species-content:v0:[A-Za-z0-9_-]{43}$")
_GENESIS_ID = re.compile(r"^dm:species-genesis:v0:[A-Za-z0-9_-]{43}$")
_RELEASE_ID = re.compile(r"^dm:species-release:v0:[A-Za-z0-9_-]{43}$")

Artifact = dict[str, Any]
SeedMap = Mapping[str, bytes]
ReleaseKind = Literal["genesis", "compatible", "branch-declaration", "fork-resolution"]


@dataclass(frozen=True)
class SpeciesServiceContext:
    registry: SpeciesRegistry
    species_id: str
    enrollment_release_id: str
    local_policy_ref: Mapping[str, Any]
    pointer_path: Path

    def __post_init__(self) -> None:
        _typed_id(self.species_id, _SPECIES_ID, "species_id")
        _typed_id(self.enrollment_release_id, _RELEASE_ID, "enrollment_release_id")
        validate_content_ref(self.local_policy_ref)


class SpeciesError(ValueError):
    """A DM-014 artifact or local transition failed closed."""

    def __init__(self, code: str, *, incomplete: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.incomplete = incomplete


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise SpeciesError(code)
    return value


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = canonical_bytes(value)
    except (CanonicalError, TypeError) as error:
        raise SpeciesError(code) from error
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise SpeciesError("species_artifact_too_large")
    return raw


def _uint(
    value: Any, code: str, *, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise SpeciesError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or _PRINTABLE.fullmatch(value) is None
    ):
        raise SpeciesError(code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _B64_32.fullmatch(value) is None:
        raise SpeciesError(code)
    try:
        unb64url(value, length=32)
    except CanonicalError as error:
        raise SpeciesError(code) from error
    return value


def _typed_id(value: Any, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SpeciesError(code)
    suffix = value.rsplit(":", 1)[1]
    _hash(suffix, code)
    return value


def _sorted_unique_texts(value: Any, code: str, *, nonempty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_SMALL_COLLECTION
        or (nonempty and not value)
        or value != sorted(set(value))
    ):
        raise SpeciesError(code)
    return [_text(item, code) for item in value]


def _sorted_objects(
    value: Any,
    code: str,
    *,
    key: str,
    nonempty: bool = False,
    maximum: int = MAX_SMALL_COLLECTION,
) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or len(value) > maximum or (nonempty and not value):
        raise SpeciesError(code)
    rows: list[Mapping[str, Any]] = []
    markers: list[str] = []
    for item in value:
        if not isinstance(item, Mapping) or not isinstance(item.get(key), str):
            raise SpeciesError(code)
        rows.append(item)
        markers.append(str(item[key]))
    if markers != sorted(markers) or len(markers) != len(set(markers)):
        raise SpeciesError(code)
    return rows


def content_ref(raw: bytes, media_type: str) -> dict[str, Any]:
    """Name exact immutable bytes without embedding any retrieval authority."""

    if not isinstance(raw, bytes) or len(raw) > MAX_CONTENT_BYTES:
        raise SpeciesError("content_size")
    media = _text(media_type, "content_media_type")
    raw_hash = hashlib.sha256(raw).digest()
    encoded = b64url(raw_hash)
    return {
        "byte_length": len(raw),
        "content_id": "dm:species-content:v0:" + encoded,
        "media_type": media,
        "sha256": encoded,
    }


def validate_content_ref(
    value: Any, *, media_type: str | None = None
) -> dict[str, Any]:
    row = _closed(
        value,
        {"byte_length", "content_id", "media_type", "sha256"},
        "content_ref_fields",
    )
    digest_value = _hash(row["sha256"], "content_ref_hash")
    content_id = _typed_id(row["content_id"], _CONTENT_ID, "content_ref_id")
    if content_id != "dm:species-content:v0:" + digest_value:
        raise SpeciesError("content_ref_id_mismatch")
    actual_media = _text(row["media_type"], "content_media_type")
    if media_type is not None and actual_media != media_type:
        raise SpeciesError("content_media_type_mismatch")
    length = _uint(row["byte_length"], "content_length", maximum=MAX_CONTENT_BYTES)
    return {
        "byte_length": length,
        "content_id": content_id,
        "media_type": actual_media,
        "sha256": digest_value,
    }


def verify_content(
    value: Any, raw: bytes, *, media_type: str | None = None
) -> dict[str, Any]:
    reference = validate_content_ref(value, media_type=media_type)
    if (
        len(raw) != reference["byte_length"]
        or b64url(hashlib.sha256(raw).digest()) != reference["sha256"]
    ):
        raise SpeciesError("content_bytes_mismatch", incomplete=True)
    return reference


def _prepare_private_path(path: Path, *, directory: bool = False) -> None:
    candidate = path if directory else path.parent
    info = candidate.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SpeciesError("species_store_parent_not_owner_only")
    if not directory and (path.exists() or path.is_symlink()):
        file_info = path.lstat()
        if (
            stat.S_ISLNK(file_info.st_mode)
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != os.geteuid()
            or stat.S_IMODE(file_info.st_mode) & 0o077
        ):
            raise SpeciesError("species_store_not_owner_only")


class SpeciesCAS:
    """Owner-only exact-byte CAS; retrieval hints never enter this store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))

    def _connect(self) -> sqlite3.Connection:
        _prepare_private_path(self.path)
        database = sqlite3.connect(
            self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None
        )
        database.row_factory = sqlite3.Row
        database.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            database.close()
            raise SpeciesError("species_cas_journal_mode")
        database.execute("PRAGMA synchronous=FULL")
        return database

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            yield database
        finally:
            database.close()

    def initialize(self) -> None:
        with self._database() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS content ("
                "content_id TEXT PRIMARY KEY, media_type TEXT NOT NULL, "
                "byte_length INTEGER NOT NULL, sha256 TEXT NOT NULL, raw BLOB NOT NULL"
                ") WITHOUT ROWID"
            )
        os.chmod(self.path, 0o600)

    def put(self, raw: bytes, media_type: str) -> dict[str, Any]:
        self.initialize()
        reference = content_ref(raw, media_type)
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
                    raise SpeciesError("species_cas_conflict")
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return reference

    def get(self, reference: Mapping[str, Any]) -> bytes:
        self.initialize()
        verified = validate_content_ref(reference)
        with self._database() as database:
            row = database.execute(
                "SELECT media_type, byte_length, sha256, raw FROM content "
                "WHERE content_id=?",
                (verified["content_id"],),
            ).fetchone()
        if row is None:
            raise SpeciesError("species_content_missing", incomplete=True)
        raw = bytes(row["raw"])
        if (
            row["media_type"] != verified["media_type"]
            or int(row["byte_length"]) != verified["byte_length"]
            or row["sha256"] != verified["sha256"]
        ):
            raise SpeciesError("species_cas_metadata_conflict")
        verify_content(verified, raw)
        return raw

    def has(self, reference: Mapping[str, Any]) -> bool:
        try:
            self.get(reference)
        except SpeciesError as error:
            if error.incomplete:
                return False
            raise
        return True


def _key_descriptor(value: Any) -> tuple[dict[str, str], bytes]:
    row = _closed(value, {"algorithm", "key_id", "public"}, "maintainer_key_fields")
    if row["algorithm"] != "Ed25519":
        raise SpeciesError("maintainer_key_algorithm")
    try:
        public = unb64url(row["public"], length=32)
        Ed25519PublicKey.from_public_bytes(public)
    except (CanonicalError, ValueError) as error:
        raise SpeciesError("maintainer_key_invalid") from error
    expected = key_id("Ed25519", public)
    if row["key_id"] != expected:
        raise SpeciesError("maintainer_key_id_mismatch")
    return {"algorithm": "Ed25519", "key_id": expected, "public": row["public"]}, public


def maintainer_policy(value: Any) -> dict[str, Any]:
    row = _closed(value, {"keys", "threshold"}, "maintainer_policy_fields")
    if not isinstance(row["keys"], list) or not 1 <= len(row["keys"]) <= MAX_KEYS:
        raise SpeciesError("maintainer_key_count")
    descriptors: list[dict[str, str]] = []
    publics: set[bytes] = set()
    ids: set[str] = set()
    for raw in row["keys"]:
        descriptor, public = _key_descriptor(raw)
        if descriptor["key_id"] in ids or public in publics:
            raise SpeciesError("maintainer_key_alias")
        ids.add(descriptor["key_id"])
        publics.add(public)
        descriptors.append(descriptor)
    if descriptors != sorted(descriptors, key=lambda item: item["key_id"]):
        raise SpeciesError("maintainer_keys_unsorted")
    threshold = _uint(row["threshold"], "maintainer_threshold", minimum=1, maximum=32)
    if threshold > len(descriptors):
        raise SpeciesError("maintainer_threshold")
    return {"keys": descriptors, "threshold": threshold}


def maintainer_policy_from_seeds(
    seeds: Sequence[bytes], threshold: int
) -> dict[str, Any]:
    descriptors = [
        {
            "algorithm": "Ed25519",
            "key_id": key_id("Ed25519", ed25519_public(seed)),
            "public": b64url(ed25519_public(seed)),
        }
        for seed in seeds
    ]
    return maintainer_policy(
        {
            "keys": sorted(descriptors, key=lambda item: item["key_id"]),
            "threshold": threshold,
        }
    )


def _policy_hash(policy: Mapping[str, Any]) -> str:
    return b64url(hashlib.sha256(canonical_bytes(maintainer_policy(policy))).digest())


def _floor(value: Any, policy: Mapping[str, Any] | None = None) -> dict[str, int]:
    row = _closed(
        value, {"minimum_key_count", "minimum_threshold"}, "maintainer_floor_fields"
    )
    key_count = _uint(
        row["minimum_key_count"], "maintainer_floor", minimum=1, maximum=32
    )
    threshold = _uint(
        row["minimum_threshold"], "maintainer_floor", minimum=1, maximum=32
    )
    if threshold > key_count:
        raise SpeciesError("maintainer_floor")
    if policy is not None:
        checked = maintainer_policy(policy)
        if len(checked["keys"]) < key_count or checked["threshold"] < threshold:
            raise SpeciesError("maintainer_policy_below_floor")
    return {"minimum_key_count": key_count, "minimum_threshold": threshold}


def derive_species_id(genesis_core: Mapping[str, Any]) -> str:
    raw = hashlib.sha256(
        SPECIES_ID_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(genesis_core)
    ).digest()
    return "dm:species:v0:" + b64url(raw)


def _manifest_entry(value: Any, *, kind: str) -> dict[str, Any]:
    if kind == "contract":
        row = _closed(
            value, {"contract_id", "contract_ref", "version"}, "genome_contract_fields"
        )
        return {
            "contract_id": _text(row["contract_id"], "genome_contract_id"),
            "contract_ref": validate_content_ref(row["contract_ref"]),
            "version": _text(row["version"], "genome_contract_version"),
        }
    if kind == "protocol":
        row = _closed(
            value,
            {"bounds_ref", "requirement_id", "requirement_ref", "version"},
            "genome_protocol_fields",
        )
        return {
            "bounds_ref": validate_content_ref(row["bounds_ref"]),
            "requirement_id": _text(row["requirement_id"], "genome_requirement_id"),
            "requirement_ref": validate_content_ref(row["requirement_ref"]),
            "version": _text(row["version"], "genome_requirement_version"),
        }
    id_name = "suite_id" if kind == "suite" else "invariant_id"
    version_name = "suite_version" if kind == "suite" else "invariant_version"
    ref_name = "suite_ref" if kind == "suite" else "invariant_ref"
    row = _closed(value, {id_name, version_name, ref_name}, f"genome_{kind}_fields")
    return {
        id_name: _text(row[id_name], f"genome_{kind}_id"),
        version_name: _text(row[version_name], f"genome_{kind}_version"),
        ref_name: validate_content_ref(row[ref_name]),
    }


def validate_genome(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "capability_contracts",
            "compatibility_requirements",
            "conformance_suites",
            "implementation_invariants",
            "protocol_requirements",
            "root_me_definition",
        },
        "genome_fields",
    )
    contracts = [
        _manifest_entry(item, kind="contract")
        for item in _sorted_objects(
            row["capability_contracts"],
            "genome_contracts",
            key="contract_id",
            nonempty=True,
        )
    ]
    protocols = [
        _manifest_entry(item, kind="protocol")
        for item in _sorted_objects(
            row["protocol_requirements"],
            "genome_protocols",
            key="requirement_id",
            nonempty=True,
        )
    ]
    suites = [
        _manifest_entry(item, kind="suite")
        for item in _sorted_objects(
            row["conformance_suites"], "genome_suites", key="suite_id", nonempty=True
        )
    ]
    invariants = [
        _manifest_entry(item, kind="invariant")
        for item in _sorted_objects(
            row["implementation_invariants"],
            "genome_invariants",
            key="invariant_id",
            nonempty=True,
        )
    ]
    requirements = _closed(
        row["compatibility_requirements"],
        {
            "forbidden_authority_changes",
            "required_contract_ids",
            "required_invariants",
            "required_suites",
            "resource_profile",
        },
        "compatibility_requirements_fields",
    )
    required_suites = [
        _manifest_entry(item, kind="suite")
        for item in _sorted_objects(
            requirements["required_suites"],
            "required_suites",
            key="suite_id",
            nonempty=True,
        )
    ]
    required_invariants = [
        _manifest_entry(item, kind="invariant")
        for item in _sorted_objects(
            requirements["required_invariants"],
            "required_invariants",
            key="invariant_id",
            nonempty=True,
        )
    ]
    required_contract_ids = _sorted_unique_texts(
        requirements["required_contract_ids"], "required_contract_ids", nonempty=True
    )
    forbidden = _sorted_unique_texts(
        requirements["forbidden_authority_changes"],
        "forbidden_authority_changes",
        nonempty=True,
    )
    declared_contracts = {item["contract_id"] for item in contracts}
    if not set(required_contract_ids) <= declared_contracts:
        raise SpeciesError("required_contract_missing")
    suite_index = {
        (item["suite_id"], item["suite_version"], canonical_bytes(item["suite_ref"]))
        for item in suites
    }
    if any(
        (item["suite_id"], item["suite_version"], canonical_bytes(item["suite_ref"]))
        not in suite_index
        for item in required_suites
    ):
        raise SpeciesError("required_suite_missing")
    invariant_index = {
        (
            item["invariant_id"],
            item["invariant_version"],
            canonical_bytes(item["invariant_ref"]),
        )
        for item in invariants
    }
    if any(
        (
            item["invariant_id"],
            item["invariant_version"],
            canonical_bytes(item["invariant_ref"]),
        )
        not in invariant_index
        for item in required_invariants
    ):
        raise SpeciesError("required_invariant_missing")
    result = {
        "capability_contracts": contracts,
        "compatibility_requirements": {
            "forbidden_authority_changes": forbidden,
            "required_contract_ids": required_contract_ids,
            "required_invariants": required_invariants,
            "required_suites": required_suites,
            "resource_profile": validate_content_ref(requirements["resource_profile"]),
        },
        "conformance_suites": suites,
        "implementation_invariants": invariants,
        "protocol_requirements": protocols,
        "root_me_definition": validate_content_ref(row["root_me_definition"]),
    }
    if _canonical(result, "genome_not_canonical") != _canonical(
        value, "genome_not_canonical"
    ):
        raise SpeciesError("genome_not_canonical")
    return result


def _artifact_ref(value: Any, *, genesis: bool = False) -> dict[str, str]:
    row = _closed(value, {"artifact_hash", "artifact_id"}, "artifact_ref_fields")
    artifact_hash = _hash(row["artifact_hash"], "artifact_ref_hash")
    pattern = _GENESIS_ID if genesis else _RELEASE_ID
    prefix = "dm:species-genesis:v0:" if genesis else "dm:species-release:v0:"
    artifact_id = _typed_id(row["artifact_id"], pattern, "artifact_ref_id")
    if artifact_id != prefix + artifact_hash:
        raise SpeciesError("artifact_ref_mismatch")
    return {"artifact_hash": artifact_hash, "artifact_id": artifact_id}


def release_ref(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"artifact_hash", "artifact_id", "epoch", "sequence", "species_id"},
        "release_ref_fields",
    )
    artifact = _artifact_ref(
        {"artifact_hash": row["artifact_hash"], "artifact_id": row["artifact_id"]}
    )
    return {
        **artifact,
        "epoch": _uint(row["epoch"], "release_ref_position"),
        "sequence": _uint(row["sequence"], "release_ref_position"),
        "species_id": _typed_id(row["species_id"], _SPECIES_ID, "species_id"),
    }


def _position_ref(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"artifact_hash", "artifact_id", "epoch", "sequence"},
        "position_ref_fields",
    )
    return {
        **_artifact_ref(
            {
                "artifact_hash": row["artifact_hash"],
                "artifact_id": row["artifact_id"],
            }
        ),
        "epoch": _uint(row["epoch"], "release_position"),
        "sequence": _uint(row["sequence"], "release_position"),
    }


def _signature(seed: bytes, role: str, preimage: bytes) -> dict[str, str]:
    public = ed25519_public(seed)
    return {
        "algorithm": "Ed25519",
        "key_id": key_id("Ed25519", public),
        "role": role,
        "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(preimage)),
    }


def _seed_map(seeds: Iterable[bytes]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for seed in seeds:
        identifier = key_id("Ed25519", ed25519_public(seed))
        if identifier in result:
            raise SpeciesError("duplicate_signing_seed")
        result[identifier] = seed
    return result


def _signatures(
    seeds: Iterable[bytes], role: str, preimage: bytes
) -> list[dict[str, str]]:
    mapped = _seed_map(seeds)
    return [
        _signature(mapped[identifier], role, preimage) for identifier in sorted(mapped)
    ]


def _wrapper(
    kind: Literal["genesis", "release"],
    body: Mapping[str, Any],
    signatures: Sequence[Mapping[str, Any]],
) -> Artifact:
    domain = GENESIS_DOMAIN if kind == "genesis" else RELEASE_DOMAIN
    prefix = "dm:species-genesis:v0:" if kind == "genesis" else "dm:species-release:v0:"
    raw_hash = digest(domain, body)
    rows = [copy.deepcopy(dict(item)) for item in signatures]
    rows.sort(key=lambda item: (str(item.get("key_id", "")), str(item.get("role", ""))))
    result: Artifact = {
        "artifact_hash": b64url(raw_hash),
        "artifact_id": prefix + b64url(raw_hash),
        "body": copy.deepcopy(dict(body)),
        "kind": kind,
        "schema": ARTIFACT_SCHEMA,
        "signatures": rows,
    }
    _canonical(result, "species_artifact_invalid")
    return result


def _verify_wrapper(
    value: Any, kind: Literal["genesis", "release"]
) -> tuple[Mapping[str, Any], bytes, list[Mapping[str, Any]]]:
    row = _closed(
        value,
        {"artifact_hash", "artifact_id", "body", "kind", "schema", "signatures"},
        "species_wrapper_fields",
    )
    if row["schema"] != ARTIFACT_SCHEMA or row["kind"] != kind:
        raise SpeciesError("species_wrapper_kind")
    body = row["body"]
    if not isinstance(body, Mapping):
        raise SpeciesError("species_body_not_object")
    domain = GENESIS_DOMAIN if kind == "genesis" else RELEASE_DOMAIN
    prefix = "dm:species-genesis:v0:" if kind == "genesis" else "dm:species-release:v0:"
    raw_hash = digest(domain, body)
    encoded = b64url(raw_hash)
    if row["artifact_hash"] != encoded or row["artifact_id"] != prefix + encoded:
        raise SpeciesError("species_artifact_id_mismatch")
    signatures = row["signatures"]
    if (
        not isinstance(signatures, list)
        or len(signatures) > MAX_SIGNATURES
        or signatures
        != sorted(
            signatures,
            key=lambda item: (str(item.get("key_id", "")), str(item.get("role", ""))),
        )
    ):
        raise SpeciesError("species_signatures_unsorted")
    permitted = (
        {"species-genesis-authorization", "species-maintainer-possession"}
        if kind == "genesis"
        else {"species-release-authorization", "species-maintainer-possession"}
    )
    seen: set[tuple[str, str]] = set()
    checked: list[Mapping[str, Any]] = []
    for item in signatures:
        signature = _closed(
            item, {"algorithm", "key_id", "role", "value"}, "species_signature_fields"
        )
        marker = (str(signature["key_id"]), str(signature["role"]))
        if (
            signature["algorithm"] != "Ed25519"
            or signature["role"] not in permitted
            or marker in seen
        ):
            raise SpeciesError("species_signature_invalid")
        _hash(signature["value"], "species_signature_value") if False else None
        try:
            unb64url(signature["value"], length=64)
        except CanonicalError as error:
            raise SpeciesError("species_signature_value") from error
        seen.add(marker)
        checked.append(signature)
    if _canonical(value, "species_artifact_invalid") != _canonical(
        {
            "artifact_hash": encoded,
            "artifact_id": prefix + encoded,
            "body": copy.deepcopy(dict(body)),
            "kind": kind,
            "schema": ARTIFACT_SCHEMA,
            "signatures": [copy.deepcopy(dict(item)) for item in checked],
        },
        "species_artifact_invalid",
    ):
        raise SpeciesError("species_artifact_not_canonical")
    return body, raw_hash, checked


def _policy_publics(policy: Mapping[str, Any]) -> dict[str, bytes]:
    checked = maintainer_policy(policy)
    result: dict[str, bytes] = {}
    for descriptor in checked["keys"]:
        _, public = _key_descriptor(descriptor)
        result[descriptor["key_id"]] = public
    return result


def _signature_status(
    signatures: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    *,
    authorization_role: str,
    authorization_preimage: bytes,
    possession_policy: Mapping[str, Any] | None,
    possession_preimage: bytes,
) -> tuple[bool, bool]:
    authorizers = _policy_publics(policy)
    possessions = (
        {} if possession_policy is None else _policy_publics(possession_policy)
    )
    valid_authorizers: set[str] = set()
    valid_possessions: set[str] = set()
    for signature in signatures:
        role = signature["role"]
        identifier = signature["key_id"]
        public = (
            authorizers.get(identifier)
            if role == authorization_role
            else possessions.get(identifier)
        )
        if public is None:
            raise SpeciesError("species_signature_unauthorized")
        preimage = (
            authorization_preimage
            if role == authorization_role
            else possession_preimage
        )
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                unb64url(signature["value"], length=64), preimage
            )
        except (InvalidSignature, CanonicalError) as error:
            raise SpeciesError("species_signature_bad") from error
        if role == authorization_role:
            valid_authorizers.add(identifier)
        else:
            valid_possessions.add(identifier)
    return (
        len(valid_authorizers) >= maintainer_policy(policy)["threshold"],
        possession_policy is None or valid_possessions == set(possessions),
    )


def _origin(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"branch_foundation", "kind", "parent_branch_release"},
        "species_origin_fields",
    )
    if row["kind"] == "primordial":
        if (
            row["branch_foundation"] is not None
            or row["parent_branch_release"] is not None
        ):
            raise SpeciesError("primordial_origin_not_null")
        return {
            "branch_foundation": None,
            "kind": "primordial",
            "parent_branch_release": None,
        }
    if (
        row["kind"] != "branch"
        or row["branch_foundation"] is None
        or row["parent_branch_release"] is None
    ):
        raise SpeciesError("branch_origin_incomplete")
    return {
        "branch_foundation": validate_branch_foundation(row["branch_foundation"]),
        "kind": "branch",
        "parent_branch_release": _position_ref(row["parent_branch_release"]),
    }


def validate_genesis_core(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "cryptographic_suite",
            "domain_version",
            "genome",
            "initial_maintainers",
            "maintainer_floor",
            "origin",
            "protocol_version",
            "species_nonce",
        },
        "genesis_core_fields",
    )
    policy = maintainer_policy(row["initial_maintainers"])
    result = {
        "cryptographic_suite": _text(row["cryptographic_suite"], "cryptographic_suite"),
        "domain_version": _uint(row["domain_version"], "domain_version"),
        "genome": validate_genome(row["genome"]),
        "initial_maintainers": policy,
        "maintainer_floor": _floor(row["maintainer_floor"], policy),
        "origin": _origin(row["origin"]),
        "protocol_version": _uint(row["protocol_version"], "protocol_version"),
        "species_nonce": _hash(row["species_nonce"], "species_nonce"),
    }
    if (
        result["protocol_version"] != 0
        or result["domain_version"] != 0
        or result["cryptographic_suite"]
        != "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"
    ):
        raise SpeciesError("genesis_protocol_suite")
    if _canonical(result, "genesis_core_not_canonical") != _canonical(
        value, "genesis_core_not_canonical"
    ):
        raise SpeciesError("genesis_core_not_canonical")
    return result


@dataclass(frozen=True)
class VerifiedGenesis:
    artifact: Mapping[str, Any]
    artifact_id: str
    artifact_hash: str
    species_id: str
    core: Mapping[str, Any]
    complete: bool


def create_species_genesis(
    genesis_core: Mapping[str, Any],
    authorizer_seeds: Sequence[bytes],
    possession_seeds: Sequence[bytes],
    *,
    created_at_ms: int,
) -> Artifact:
    core = validate_genesis_core(genesis_core)
    body = {
        "created_at_ms": _uint(created_at_ms, "genesis_created_at"),
        "genesis_core": core,
        "schema": GENESIS_SCHEMA,
        "species_id": derive_species_id(core),
    }
    raw_hash = digest(GENESIS_DOMAIN, body)
    signatures = _signatures(
        authorizer_seeds,
        "species-genesis-authorization",
        domain_bytes(GENESIS_DOMAIN, body),
    )
    signatures.extend(
        _signatures(
            possession_seeds,
            "species-maintainer-possession",
            GENESIS_DOMAIN.encode("ascii") + b"\x00" + raw_hash,
        )
    )
    return _wrapper("genesis", body, signatures)


def verify_species_genesis(
    value: Any, *, forbidden_public_keys: Iterable[bytes] = ()
) -> VerifiedGenesis:
    body, raw_hash, signatures = _verify_wrapper(value, "genesis")
    row = _closed(
        body,
        {"created_at_ms", "genesis_core", "schema", "species_id"},
        "genesis_body_fields",
    )
    if row["schema"] != GENESIS_SCHEMA:
        raise SpeciesError("genesis_schema")
    core = validate_genesis_core(row["genesis_core"])
    species_id = _typed_id(row["species_id"], _SPECIES_ID, "species_id")
    if species_id != derive_species_id(core):
        raise SpeciesError("species_id_mismatch")
    _uint(row["created_at_ms"], "genesis_created_at")
    public = set(_policy_publics(core["initial_maintainers"]).values())
    if public & set(forbidden_public_keys):
        raise SpeciesError("maintainer_cross_role_alias")
    authorization, possession = _signature_status(
        signatures,
        core["initial_maintainers"],
        authorization_role="species-genesis-authorization",
        authorization_preimage=domain_bytes(GENESIS_DOMAIN, body),
        possession_policy=core["initial_maintainers"],
        possession_preimage=GENESIS_DOMAIN.encode("ascii") + b"\x00" + raw_hash,
    )
    return VerifiedGenesis(
        artifact=copy.deepcopy(dict(value)),
        artifact_id=str(value["artifact_id"]),
        artifact_hash=b64url(raw_hash),
        species_id=species_id,
        core=core,
        complete=authorization and possession,
    )


def _delta_set(value: Any) -> dict[str, list[str]]:
    row = _closed(value, {"added", "changed", "removed"}, "contract_delta_fields")
    return {
        "added": _sorted_unique_texts(row["added"], "contract_delta"),
        "changed": _sorted_unique_texts(row["changed"], "contract_delta"),
        "removed": _sorted_unique_texts(row["removed"], "contract_delta"),
    }


def _evidence_link(value: Any) -> dict[str, Any]:
    row = _closed(value, {"root_ref", "row_count"}, "evidence_link_fields")
    return {
        "root_ref": validate_content_ref(
            row["root_ref"],
            media_type="application/vnd.daimon.species-evidence-root.v0+json",
        ),
        "row_count": _uint(
            row["row_count"], "evidence_row_count", maximum=MAX_EVIDENCE_ROWS
        ),
    }


def validate_compatibility_report(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "base_release",
            "candidate_genome_hash",
            "contract_delta",
            "invariant_evidence",
            "overall_verdict",
            "protocol_delta",
            "schema",
            "test_evidence",
        },
        "compatibility_report_fields",
    )
    if row["schema"] != "daimon-species-compatibility-report/v0":
        raise SpeciesError("compatibility_report_schema")
    if row["overall_verdict"] not in {"genesis", "compatible", "incompatible"}:
        raise SpeciesError("compatibility_report_verdict")
    protocol_rows = _sorted_objects(
        row["protocol_delta"], "protocol_delta", key="requirement_id"
    )
    protocol_delta: list[dict[str, Any]] = []
    for value_row in protocol_rows:
        item = _closed(
            value_row,
            {"candidate_hash", "classification", "prior_hash", "requirement_id"},
            "protocol_delta_fields",
        )
        prior = (
            None
            if item["prior_hash"] is None
            else _hash(item["prior_hash"], "protocol_delta_hash")
        )
        candidate = (
            None
            if item["candidate_hash"] is None
            else _hash(item["candidate_hash"], "protocol_delta_hash")
        )
        classification = item["classification"]
        if classification not in {
            "added",
            "removed",
            "compatible-change",
            "breaking-change",
        }:
            raise SpeciesError("protocol_delta_classification")
        if (
            (prior is None and candidate is None)
            or (classification == "added" and prior is not None)
            or (classification == "removed" and candidate is not None)
            or (
                classification in {"compatible-change", "breaking-change"}
                and (prior is None or candidate is None or prior == candidate)
            )
        ):
            raise SpeciesError("protocol_delta_inconsistent")
        protocol_delta.append(
            {
                "candidate_hash": candidate,
                "classification": classification,
                "prior_hash": prior,
                "requirement_id": _text(item["requirement_id"], "protocol_delta_id"),
            }
        )
    result = {
        "base_release": None
        if row["base_release"] is None
        else _position_ref(row["base_release"]),
        "candidate_genome_hash": _hash(
            row["candidate_genome_hash"], "candidate_genome_hash"
        ),
        "contract_delta": _delta_set(row["contract_delta"]),
        "invariant_evidence": _evidence_link(row["invariant_evidence"]),
        "overall_verdict": row["overall_verdict"],
        "protocol_delta": protocol_delta,
        "schema": "daimon-species-compatibility-report/v0",
        "test_evidence": _evidence_link(row["test_evidence"]),
    }
    if _canonical(result, "compatibility_report_not_canonical") != _canonical(
        value, "compatibility_report_not_canonical"
    ):
        raise SpeciesError("compatibility_report_not_canonical")
    return result


def _breaking_target(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("kind") not in {
        "bound",
        "contract",
        "protocol",
        "required-output",
    }:
        raise SpeciesError("breaking_target")
    kind = value["kind"]
    expected = (
        {"kind", "contract_id"}
        if kind == "contract"
        else {"kind", "requirement_id"}
        if kind in {"bound", "protocol"}
        else {"kind", "case_id", "suite_id", "suite_version"}
    )
    row = _closed(value, expected, "breaking_target_fields")
    result = {"kind": kind}
    for name in sorted(expected - {"kind"}):
        result[name] = _text(row[name], "breaking_target_value")
    return result


def validate_branch_foundation(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "branch_nonce",
            "breaking_delta",
            "child_genome",
            "child_implementation_bundle",
            "child_initial_maintainers",
            "child_maintainer_floor",
            "child_species_nonce",
            "incompatibility_report",
            "parent_base_release",
            "parent_species_id",
            "schema",
        },
        "branch_foundation_fields",
    )
    if row["schema"] != "daimon-species-branch-foundation/v0":
        raise SpeciesError("branch_foundation_schema")
    policy = maintainer_policy(row["child_initial_maintainers"])
    raw_deltas = _sorted_objects(
        row["breaking_delta"],
        "breaking_delta",
        key="delta_id",
        nonempty=True,
    )
    deltas: list[dict[str, Any]] = []
    targets: set[bytes] = set()
    for raw in raw_deltas:
        item = _closed(
            raw,
            {"child_hash", "delta_id", "parent_hash", "reason_code", "target"},
            "breaking_delta_fields",
        )
        target = _breaking_target(item["target"])
        target_marker = canonical_bytes(target)
        if target_marker in targets:
            raise SpeciesError("breaking_delta_target_duplicate")
        targets.add(target_marker)
        parent_hash = (
            None
            if item["parent_hash"] is None
            else _hash(item["parent_hash"], "breaking_delta_hash")
        )
        child_hash = (
            None
            if item["child_hash"] is None
            else _hash(item["child_hash"], "breaking_delta_hash")
        )
        reason = item["reason_code"]
        if reason not in {
            "added-breaking",
            "changed-bound",
            "changed-contract",
            "changed-protocol",
            "changed-required-output",
            "removed",
        }:
            raise SpeciesError("breaking_delta_reason")
        if (
            (parent_hash is None and child_hash is None)
            or (reason == "added-breaking" and parent_hash is not None)
            or (reason == "removed" and child_hash is not None)
            or (
                reason not in {"added-breaking", "removed"}
                and (
                    parent_hash is None
                    or child_hash is None
                    or parent_hash == child_hash
                )
            )
        ):
            raise SpeciesError("breaking_delta_inconsistent")
        deltas.append(
            {
                "child_hash": child_hash,
                "delta_id": _text(item["delta_id"], "breaking_delta_id"),
                "parent_hash": parent_hash,
                "reason_code": reason,
                "target": target,
            }
        )
    report = _closed(
        row["incompatibility_report"],
        {
            "child_candidate_hash",
            "overall_verdict",
            "parent_requirements_hash",
            "test_evidence",
        },
        "incompatibility_report_fields",
    )
    if report["overall_verdict"] != "deliberately-incompatible":
        raise SpeciesError("incompatibility_verdict")
    parent_release = release_ref(row["parent_base_release"])
    parent_species = _typed_id(
        row["parent_species_id"], _SPECIES_ID, "parent_species_id"
    )
    if parent_release["species_id"] != parent_species:
        raise SpeciesError("branch_parent_species_mismatch")
    result = {
        "branch_nonce": _hash(row["branch_nonce"], "branch_nonce"),
        "breaking_delta": deltas,
        "child_genome": validate_genome(row["child_genome"]),
        "child_implementation_bundle": validate_content_ref(
            row["child_implementation_bundle"],
            media_type="application/vnd.daimon.species-implementation-bundle.v0+json",
        ),
        "child_initial_maintainers": policy,
        "child_maintainer_floor": _floor(row["child_maintainer_floor"], policy),
        "child_species_nonce": _hash(row["child_species_nonce"], "child_species_nonce"),
        "incompatibility_report": {
            "child_candidate_hash": _hash(
                report["child_candidate_hash"], "child_candidate_hash"
            ),
            "overall_verdict": "deliberately-incompatible",
            "parent_requirements_hash": _hash(
                report["parent_requirements_hash"], "parent_requirements_hash"
            ),
            "test_evidence": _evidence_link(report["test_evidence"]),
        },
        "parent_base_release": parent_release,
        "parent_species_id": parent_species,
        "schema": "daimon-species-branch-foundation/v0",
    }
    if _canonical(result, "branch_foundation_not_canonical") != _canonical(
        value, "branch_foundation_not_canonical"
    ):
        raise SpeciesError("branch_foundation_not_canonical")
    return result


def _fork_resolution(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {"closed_epoch", "closure_cursor", "common_predecessor", "competing_heads"},
        "fork_resolution_fields",
    )
    cursor = _closed(
        row["closure_cursor"],
        {"epoch", "max_sequence", "occupied_count", "occupied_manifest_ref"},
        "closure_cursor_fields",
    )
    heads = (
        [_position_ref(item) for item in row["competing_heads"]]
        if isinstance(row["competing_heads"], list)
        else []
    )
    if len(heads) < 2 or len(heads) > MAX_SMALL_COLLECTION:
        raise SpeciesError("fork_resolution_heads")
    head_keys = [
        (item["epoch"], item["sequence"], item["artifact_id"]) for item in heads
    ]
    if head_keys != sorted(set(head_keys)):
        raise SpeciesError("fork_resolution_heads_unsorted")
    return {
        "closed_epoch": _uint(row["closed_epoch"], "closed_epoch"),
        "closure_cursor": {
            "epoch": _uint(cursor["epoch"], "closure_epoch"),
            "max_sequence": _uint(cursor["max_sequence"], "closure_max_sequence"),
            "occupied_count": _uint(
                cursor["occupied_count"], "closure_count", minimum=2
            ),
            "occupied_manifest_ref": validate_content_ref(
                cursor["occupied_manifest_ref"],
                media_type="application/vnd.daimon.species-fork-closure-root.v0+json",
            ),
        },
        "common_predecessor": _position_ref(row["common_predecessor"]),
        "competing_heads": heads,
    }


def validate_release_body(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "authorizing_policy_hash",
            "branch_declaration",
            "compatibility_report",
            "fork_resolution",
            "genesis",
            "genome",
            "implementation_bundle",
            "issued_at_ms",
            "next_maintainers",
            "position",
            "previous_release",
            "release_kind",
            "release_label",
            "schema",
            "species_id",
        },
        "release_body_fields",
    )
    if row["schema"] != RELEASE_SCHEMA or row["release_kind"] not in {
        "branch-declaration",
        "compatible",
        "fork-resolution",
        "genesis",
    }:
        raise SpeciesError("release_schema_kind")
    position = _closed(
        row["position"], {"epoch", "sequence"}, "release_position_fields"
    )
    kind: ReleaseKind = row["release_kind"]
    branch = (
        None
        if row["branch_declaration"] is None
        else validate_branch_foundation(row["branch_declaration"])
    )
    resolution = (
        None
        if row["fork_resolution"] is None
        else _fork_resolution(row["fork_resolution"])
    )
    if (kind == "branch-declaration") != (branch is not None) or (
        kind == "fork-resolution"
    ) != (resolution is not None):
        raise SpeciesError("release_kind_payload_mismatch")
    if kind in {"genesis", "compatible"} and (
        branch is not None or resolution is not None
    ):
        raise SpeciesError("release_kind_payload_mismatch")
    result = {
        "authorizing_policy_hash": _hash(
            row["authorizing_policy_hash"], "authorizing_policy_hash"
        ),
        "branch_declaration": branch,
        "compatibility_report": validate_compatibility_report(
            row["compatibility_report"]
        ),
        "fork_resolution": resolution,
        "genesis": _artifact_ref(row["genesis"], genesis=True),
        "genome": validate_genome(row["genome"]),
        "implementation_bundle": validate_content_ref(
            row["implementation_bundle"],
            media_type="application/vnd.daimon.species-implementation-bundle.v0+json",
        ),
        "issued_at_ms": _uint(row["issued_at_ms"], "release_issued_at"),
        "next_maintainers": maintainer_policy(row["next_maintainers"]),
        "position": {
            "epoch": _uint(position["epoch"], "release_epoch"),
            "sequence": _uint(position["sequence"], "release_sequence"),
        },
        "previous_release": None
        if row["previous_release"] is None
        else _position_ref(row["previous_release"]),
        "release_kind": kind,
        "release_label": _text(row["release_label"], "release_label"),
        "schema": RELEASE_SCHEMA,
        "species_id": _typed_id(row["species_id"], _SPECIES_ID, "species_id"),
    }
    if _canonical(result, "release_body_not_canonical") != _canonical(
        value, "release_body_not_canonical"
    ):
        raise SpeciesError("release_body_not_canonical")
    return result


def create_species_release(
    body: Mapping[str, Any],
    authorizer_seeds: Sequence[bytes],
    possession_seeds: Sequence[bytes] = (),
) -> Artifact:
    checked = validate_release_body(body)
    raw_hash = digest(RELEASE_DOMAIN, checked)
    signatures = _signatures(
        authorizer_seeds,
        "species-release-authorization",
        domain_bytes(RELEASE_DOMAIN, checked),
    )
    signatures.extend(
        _signatures(
            possession_seeds,
            "species-maintainer-possession",
            RELEASE_DOMAIN.encode("ascii") + b"\x00" + raw_hash,
        )
    )
    return _wrapper("release", checked, signatures)


@dataclass(frozen=True)
class VerifiedRelease:
    artifact: Mapping[str, Any]
    artifact_id: str
    artifact_hash: str
    body: Mapping[str, Any]
    complete: bool


def verify_species_release(
    value: Any,
    *,
    authorizing_policy: Mapping[str, Any],
    possession_required: bool,
    maintainer_floor: Mapping[str, Any],
    forbidden_public_keys: Iterable[bytes] = (),
) -> VerifiedRelease:
    raw_body, raw_hash, signatures = _verify_wrapper(value, "release")
    body = validate_release_body(raw_body)
    if body["authorizing_policy_hash"] != _policy_hash(authorizing_policy):
        raise SpeciesError("release_authorizing_policy_hash")
    _floor(maintainer_floor, body["next_maintainers"])
    public = set(_policy_publics(body["next_maintainers"]).values())
    if public & set(forbidden_public_keys):
        raise SpeciesError("maintainer_cross_role_alias")
    possession_policy = body["next_maintainers"] if possession_required else None
    authorization, possession = _signature_status(
        signatures,
        authorizing_policy,
        authorization_role="species-release-authorization",
        authorization_preimage=domain_bytes(RELEASE_DOMAIN, body),
        possession_policy=possession_policy,
        possession_preimage=RELEASE_DOMAIN.encode("ascii") + b"\x00" + raw_hash,
    )
    return VerifiedRelease(
        artifact=copy.deepcopy(dict(value)),
        artifact_id=str(value["artifact_id"]),
        artifact_hash=b64url(raw_hash),
        body=body,
        complete=authorization and possession,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpeciesError("content_json_duplicate_key")
        result[key] = value
    return result


def _content_json(cas: SpeciesCAS, reference: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = cas.get(reference)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SpeciesError("content_json_invalid") from error
    if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
        raise SpeciesError("content_json_not_canonical")
    return value


def _resource_profile(
    cas: SpeciesCAS, reference: Mapping[str, Any]
) -> Mapping[str, Any]:
    verified = validate_content_ref(
        reference,
        media_type="application/vnd.daimon.species-resource-profile.v0+json",
    )
    value = _content_json(cas, verified)
    ResourceProfile.validate(value)
    return value


def _runner_profile(cas: SpeciesCAS, reference: Mapping[str, Any]) -> dict[str, Any]:
    verified = validate_content_ref(
        reference,
        media_type="application/vnd.daimon.species-runner-profile.v0+json",
    )
    row = _closed(
        _content_json(cas, verified),
        {
            "resource_profile_ref",
            "result_encoding",
            "runner_conformance_ref",
            "runner_version",
            "schema",
            "wasi_semantics_ref",
        },
        "runner_profile_fields",
    )
    if (
        row["schema"] != "species-runner-profile/v0"
        or row["runner_version"] != RUNNER_VERSION
        or row["result_encoding"] != "daimon-test-result-jcs/v0"
    ):
        raise SpeciesError("runner_profile_unsupported")
    semantics_ref = validate_content_ref(row["wasi_semantics_ref"])
    conformance_ref = validate_content_ref(row["runner_conformance_ref"])
    semantics = _content_json(cas, semantics_ref)
    conformance = _closed(
        _content_json(cas, conformance_ref),
        {"runner_version", "schema", "verdict"},
        "runner_conformance_fields",
    )
    if (
        semantics.get("schema") != "species-wasi-semantics/v0"
        or semantics.get("execution_model") != "wasm32-wasi-preview1-deterministic/v0"
        or conformance["schema"] != "species-runner-conformance/v0"
        or conformance["runner_version"] != RUNNER_VERSION
        or conformance["verdict"] != "pass"
    ):
        raise SpeciesError("runner_conformance_failed")
    resource_ref = validate_content_ref(row["resource_profile_ref"])
    _resource_profile(cas, resource_ref)
    return {
        "resource_profile_ref": resource_ref,
        "result_encoding": "daimon-test-result-jcs/v0",
        "runner_conformance_ref": conformance_ref,
        "runner_version": RUNNER_VERSION,
        "schema": "species-runner-profile/v0",
        "wasi_semantics_ref": semantics_ref,
    }


def _suite_manifest(
    cas: SpeciesCAS,
    reference: Mapping[str, Any],
    *,
    invariant: bool,
) -> dict[str, Any]:
    schema = (
        "species-invariant-manifest/v0" if invariant else "species-suite-manifest/v0"
    )
    media = f"application/vnd.daimon.{schema.replace('/', '.')}+json"
    checked_ref = validate_content_ref(reference, media_type=media)
    id_name = "invariant_id" if invariant else "suite_id"
    version_name = "invariant_version" if invariant else "suite_version"
    extra = {"definition_ref"} if invariant else set()
    row = _closed(
        _content_json(cas, checked_ref),
        {"cases", id_name, "runner_profile_ref", "schema", version_name} | extra,
        "suite_manifest_fields",
    )
    if row["schema"] != schema:
        raise SpeciesError("suite_manifest_schema")
    cases = _sorted_objects(
        row["cases"],
        "suite_cases",
        key="case_id",
        nonempty=True,
        maximum=MAX_EVIDENCE_ROWS,
    )
    checked_cases: list[dict[str, Any]] = []
    for value_case in cases:
        case = _closed(
            value_case,
            {"case_id", "entrypoint_id", "expected_result_ref", "input_ref"},
            "suite_case_fields",
        )
        checked_cases.append(
            {
                "case_id": _text(case["case_id"], "case_id"),
                "entrypoint_id": _text(case["entrypoint_id"], "entrypoint_id"),
                "expected_result_ref": validate_content_ref(
                    case["expected_result_ref"]
                ),
                "input_ref": validate_content_ref(case["input_ref"]),
            }
        )
    result: dict[str, Any] = {
        "cases": checked_cases,
        id_name: _text(row[id_name], "suite_id"),
        "runner_profile_ref": validate_content_ref(row["runner_profile_ref"]),
        "schema": schema,
        version_name: _text(row[version_name], "suite_version"),
    }
    if invariant:
        result["definition_ref"] = validate_content_ref(row["definition_ref"])
        cas.get(result["definition_ref"])
    _runner_profile(cas, result["runner_profile_ref"])
    if canonical_bytes(result) != canonical_bytes(row):
        raise SpeciesError("suite_manifest_not_canonical")
    return result


def _bundle_manifest(
    cas: SpeciesCAS,
    reference: Mapping[str, Any],
    *,
    seen: set[str] | None = None,
    depth: int = 0,
    budget: dict[str, int] | None = None,
) -> tuple[dict[str, Any], bytes, dict[str, bytes], dict[str, Mapping[str, bytes]]]:
    if depth > MAX_BUNDLE_DEPENDENCY_DEPTH:
        raise SpeciesError("bundle_dependency_depth")
    checked_ref = validate_content_ref(
        reference,
        media_type="application/vnd.daimon.species-implementation-bundle.v0+json",
    )
    closure = {"bytes": 0, "nodes": 0} if budget is None else budget
    closure["nodes"] += 1
    closure["bytes"] += checked_ref["byte_length"]
    if closure["nodes"] > MAX_BUNDLE_DEPENDENCY_NODES:
        raise SpeciesError("bundle_dependency_nodes")
    if closure["bytes"] > MAX_BUNDLE_CLOSURE_BYTES:
        raise SpeciesError("bundle_closure_bytes")
    lineage = set() if seen is None else set(seen)
    if checked_ref["content_id"] in lineage:
        raise SpeciesError("bundle_dependency_cycle")
    lineage.add(checked_ref["content_id"])
    row = _closed(
        _content_json(cas, checked_ref),
        {"dependencies", "entrypoints", "files", "module", "schema"},
        "bundle_manifest_fields",
    )
    if row["schema"] != "species-implementation-bundle/v0":
        raise SpeciesError("bundle_manifest_schema")
    entrypoints = _sorted_objects(
        row["entrypoints"], "bundle_entrypoints", key="entrypoint_id", nonempty=True
    )
    checked_entrypoints: list[dict[str, str]] = []
    exports: set[str] = set()
    for raw_entrypoint in entrypoints:
        item = _closed(
            raw_entrypoint, {"entrypoint_id", "export_name"}, "bundle_entrypoint_fields"
        )
        export = _text(item["export_name"], "bundle_export_name")
        if export in exports:
            raise SpeciesError("bundle_export_alias")
        exports.add(export)
        checked_entrypoints.append(
            {
                "entrypoint_id": _text(item["entrypoint_id"], "bundle_entrypoint_id"),
                "export_name": export,
            }
        )
    files = _sorted_objects(row["files"], "bundle_files", key="path", maximum=4096)
    checked_files: list[dict[str, Any]] = []
    materialized: dict[str, bytes] = {}
    for raw_file in files:
        item = _closed(raw_file, {"content", "mode", "path"}, "bundle_file_fields")
        if item["mode"] != "read-only":
            raise SpeciesError("bundle_file_mode")
        path = _text(item["path"], "bundle_file_path", maximum=512)
        parts = path.split("/")
        if (
            "\\" in path
            or path.startswith("/")
            or path.endswith("/")
            or len(parts) > 32
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise SpeciesError("bundle_file_path")
        content = validate_content_ref(item["content"])
        closure["bytes"] += content["byte_length"]
        if closure["bytes"] > MAX_BUNDLE_CLOSURE_BYTES:
            raise SpeciesError("bundle_closure_bytes")
        materialized[path] = cas.get(content)
        checked_files.append({"content": content, "mode": "read-only", "path": path})
    dependencies = row["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) > MAX_SMALL_COLLECTION:
        raise SpeciesError("bundle_dependencies")
    checked_dependencies = [validate_content_ref(item) for item in dependencies]
    dependency_ids = [item["content_id"] for item in checked_dependencies]
    if dependency_ids != sorted(set(dependency_ids)):
        raise SpeciesError("bundle_dependencies_unsorted")
    dependency_files: dict[str, Mapping[str, bytes]] = {}
    for dependency in checked_dependencies:
        _, _, nested_files, nested_dependencies = _bundle_manifest(
            cas,
            dependency,
            seen=lineage,
            depth=depth + 1,
            budget=closure,
        )
        dependency_files[dependency["content_id"]] = nested_files
        for identifier, nested in nested_dependencies.items():
            if identifier in dependency_files:
                raise SpeciesError("bundle_dependency_alias")
            dependency_files[identifier] = nested
    module_ref = validate_content_ref(row["module"], media_type="application/wasm")
    closure["bytes"] += module_ref["byte_length"]
    if closure["bytes"] > MAX_BUNDLE_CLOSURE_BYTES:
        raise SpeciesError("bundle_closure_bytes")
    module_bytes = cas.get(module_ref)
    result = {
        "dependencies": checked_dependencies,
        "entrypoints": checked_entrypoints,
        "files": checked_files,
        "module": module_ref,
        "schema": "species-implementation-bundle/v0",
    }
    if canonical_bytes(result) != canonical_bytes(row):
        raise SpeciesError("bundle_manifest_not_canonical")
    return result, module_bytes, materialized, dependency_files


def _evidence_root(
    cas: SpeciesCAS, reference: Mapping[str, Any], *, kind: str, row_count: int
) -> list[Mapping[str, Any]]:
    checked_ref = validate_content_ref(
        reference,
        media_type="application/vnd.daimon.species-evidence-root.v0+json",
    )
    root = _closed(
        _content_json(cas, checked_ref),
        {"kind", "pages", "row_count", "schema"},
        "evidence_root_fields",
    )
    if (
        root["schema"] != "species-evidence-root/v0"
        or root["kind"] != kind
        or root["row_count"] != row_count
    ):
        raise SpeciesError("evidence_root_mismatch")
    if not isinstance(root["pages"], list):
        raise SpeciesError("evidence_pages")
    rows: list[Mapping[str, Any]] = []
    for index, raw_link in enumerate(root["pages"]):
        link = _closed(
            raw_link,
            {"first_key", "last_key", "page_index", "page_ref", "row_count"},
            "evidence_page_link_fields",
        )
        if link["page_index"] != index or not 1 <= link["row_count"] <= 64:
            raise SpeciesError("evidence_page_link")
        page_ref = validate_content_ref(
            link["page_ref"],
            media_type="application/vnd.daimon.species-evidence-page.v0+json",
        )
        page = _closed(
            _content_json(cas, page_ref),
            {"kind", "page_index", "rows", "schema"},
            "evidence_page_fields",
        )
        if (
            page["schema"] != "species-evidence-page/v0"
            or page["kind"] != kind
            or page["page_index"] != index
            or not isinstance(page["rows"], list)
            or len(page["rows"]) != link["row_count"]
        ):
            raise SpeciesError("evidence_page_mismatch")
        page_rows = [copy.deepcopy(dict(item)) for item in page["rows"]]
        if (
            not page_rows
            or link["first_key"] != _evidence_key(page_rows[0], kind)
            or link["last_key"] != _evidence_key(page_rows[-1], kind)
        ):
            raise SpeciesError("evidence_page_range")
        rows.extend(page_rows)
    keys = [_evidence_key(item, kind) for item in rows]
    if len(rows) != row_count or keys != sorted(keys) or len(keys) != len(set(keys)):
        raise SpeciesError("evidence_rows_mismatch")
    return rows


def _evidence_key(row: Mapping[str, Any], kind: str) -> str:
    id_name = "invariant_id" if kind == "invariant" else "suite_id"
    version_name = "invariant_version" if kind == "invariant" else "suite_version"
    try:
        return f"{row[id_name]}\x00{row[version_name]}\x00{row['case_id']}"
    except KeyError as error:
        raise SpeciesError("evidence_row_key") from error


def _store_evidence_pages(
    cas: SpeciesCAS, kind: str, rows: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    links: list[dict[str, Any]] = []
    for page_index, start in enumerate(range(0, len(rows), 64)):
        page_rows = [copy.deepcopy(dict(item)) for item in rows[start : start + 64]]
        page = {
            "kind": kind,
            "page_index": page_index,
            "rows": page_rows,
            "schema": "species-evidence-page/v0",
        }
        page_ref = cas.put(
            canonical_bytes(page),
            "application/vnd.daimon.species-evidence-page.v0+json",
        )
        links.append(
            {
                "first_key": _evidence_key(page_rows[0], kind),
                "last_key": _evidence_key(page_rows[-1], kind),
                "page_index": page_index,
                "page_ref": page_ref,
                "row_count": len(page_rows),
            }
        )
    root = {
        "kind": kind,
        "pages": links,
        "row_count": len(rows),
        "schema": "species-evidence-root/v0",
    }
    root_ref = cas.put(
        canonical_bytes(root),
        "application/vnd.daimon.species-evidence-root.v0+json",
    )
    return {"root_ref": root_ref, "row_count": len(rows)}


def _entry_hash(value: Mapping[str, Any]) -> str:
    return b64url(hashlib.sha256(canonical_bytes(value)).digest())


def _genome_delta(
    base: Mapping[str, Any] | None, candidate: Mapping[str, Any]
) -> tuple[dict[str, list[str]], list[dict[str, Any]], bool]:
    if base is None:
        return {"added": [], "changed": [], "removed": []}, [], True
    base_contracts = {
        item["contract_id"]: item for item in base["capability_contracts"]
    }
    candidate_contracts = {
        item["contract_id"]: item for item in candidate["capability_contracts"]
    }
    added = sorted(set(candidate_contracts) - set(base_contracts))
    removed = sorted(set(base_contracts) - set(candidate_contracts))
    changed = sorted(
        identifier
        for identifier in set(base_contracts) & set(candidate_contracts)
        if canonical_bytes(base_contracts[identifier])
        != canonical_bytes(candidate_contracts[identifier])
    )
    base_protocol = {
        item["requirement_id"]: item for item in base["protocol_requirements"]
    }
    candidate_protocol = {
        item["requirement_id"]: item for item in candidate["protocol_requirements"]
    }
    protocol_delta: list[dict[str, Any]] = []
    for identifier in sorted(set(base_protocol) | set(candidate_protocol)):
        prior = base_protocol.get(identifier)
        current = candidate_protocol.get(identifier)
        if (
            prior is not None
            and current is not None
            and canonical_bytes(prior) == canonical_bytes(current)
        ):
            continue
        classification = (
            "added"
            if prior is None
            else "removed"
            if current is None
            else "breaking-change"
        )
        protocol_delta.append(
            {
                "candidate_hash": None if current is None else _entry_hash(current),
                "classification": classification,
                "prior_hash": None if prior is None else _entry_hash(prior),
                "requirement_id": identifier,
            }
        )
    required = base["compatibility_requirements"]
    candidate_required = candidate["compatibility_requirements"]

    def contains_rows(name: str) -> bool:
        prior_rows = {canonical_bytes(item) for item in required[name]}
        next_rows = {canonical_bytes(item) for item in candidate_required[name]}
        return prior_rows <= next_rows

    monotonic = (
        not removed
        and not changed
        and all(item["classification"] == "added" for item in protocol_delta)
        and canonical_bytes(base["root_me_definition"])
        == canonical_bytes(candidate["root_me_definition"])
        and canonical_bytes(required["resource_profile"])
        == canonical_bytes(candidate_required["resource_profile"])
        and set(required["required_contract_ids"])
        <= set(candidate_required["required_contract_ids"])
        and set(required["forbidden_authority_changes"])
        <= set(candidate_required["forbidden_authority_changes"])
        and contains_rows("required_suites")
        and contains_rows("required_invariants")
        and {canonical_bytes(item) for item in base["conformance_suites"]}
        <= {canonical_bytes(item) for item in candidate["conformance_suites"]}
        and {canonical_bytes(item) for item in base["implementation_invariants"]}
        <= {canonical_bytes(item) for item in candidate["implementation_invariants"]}
    )
    return (
        {"added": added, "changed": changed, "removed": removed},
        protocol_delta,
        monotonic,
    )


class CompatibilityVerifier:
    """Recompute predecessor-selected exact evidence in the pinned sandbox."""

    def __init__(
        self, cas: SpeciesCAS, runner: DeterministicWasiRunner | None = None
    ) -> None:
        self.cas = cas
        self.runner = DeterministicWasiRunner() if runner is None else runner

    def _validate_genome_content(self, genome: Mapping[str, Any]) -> None:
        self.cas.get(genome["root_me_definition"])
        for item in genome["capability_contracts"]:
            self.cas.get(item["contract_ref"])
        for item in genome["protocol_requirements"]:
            self.cas.get(item["requirement_ref"])
            self.cas.get(item["bounds_ref"])
        _resource_profile(
            self.cas, genome["compatibility_requirements"]["resource_profile"]
        )
        for item in genome["conformance_suites"]:
            _suite_manifest(self.cas, item["suite_ref"], invariant=False)
        for item in genome["implementation_invariants"]:
            _suite_manifest(self.cas, item["invariant_ref"], invariant=True)

    def _validate_selected_execution(self, requirements: Mapping[str, Any]) -> None:
        signed_resource_ref = requirements["resource_profile"]
        profile = ResourceProfile.validate(
            _resource_profile(self.cas, signed_resource_ref)
        )
        case_count = 0
        selected = [
            (item["suite_ref"], False) for item in requirements["required_suites"]
        ] + [
            (item["invariant_ref"], True)
            for item in requirements["required_invariants"]
        ]
        for manifest_ref, invariant in selected:
            manifest = _suite_manifest(self.cas, manifest_ref, invariant=invariant)
            runner = _runner_profile(self.cas, manifest["runner_profile_ref"])
            if canonical_bytes(runner["resource_profile_ref"]) != canonical_bytes(
                signed_resource_ref
            ):
                raise SpeciesError("selected_runner_resource_profile_mismatch")
            case_count += len(manifest["cases"])
        if (
            case_count > profile.case_count
            or case_count * profile.cpu_fuel > profile.aggregate_cpu_fuel
            or case_count * profile.wall_timeout_ms > profile.aggregate_wall_timeout_ms
        ):
            raise SpeciesError("selected_execution_aggregate_limit")

    def _run_manifest(
        self,
        manifest_ref: Mapping[str, Any],
        bundle_ref: Mapping[str, Any],
        *,
        invariant: bool,
    ) -> list[dict[str, Any]]:
        manifest = _suite_manifest(self.cas, manifest_ref, invariant=invariant)
        runner_profile = _runner_profile(self.cas, manifest["runner_profile_ref"])
        resource_profile = _resource_profile(
            self.cas, runner_profile["resource_profile_ref"]
        )
        bundle, module, files, dependencies = _bundle_manifest(self.cas, bundle_ref)
        entrypoints = {
            item["entrypoint_id"]: item["export_name"] for item in bundle["entrypoints"]
        }
        rows: list[dict[str, Any]] = []
        id_name = "invariant_id" if invariant else "suite_id"
        version_name = "invariant_version" if invariant else "suite_version"
        for case in manifest["cases"]:
            export_name = entrypoints.get(case["entrypoint_id"])
            if export_name is None:
                raise SpeciesError("suite_entrypoint_missing")
            input_bytes = self.cas.get(case["input_ref"])
            expected = self.cas.get(case["expected_result_ref"])
            try:
                execution = self.runner.run(
                    case_id=case["case_id"],
                    module_bytes=module,
                    export_name=export_name,
                    input_bytes=input_bytes,
                    bundle_files=files,
                    dependency_files=dependencies,
                    resource_profile=resource_profile,
                )
            except SpeciesRunnerError as error:
                if error.incomplete:
                    raise SpeciesError(error.code, incomplete=True) from error
                raise SpeciesError(error.code) from error
            actual_ref = self.cas.put(
                execution.result_bytes,
                "application/vnd.daimon.daimon-test-result-jcs.v0+json",
            )
            verdict = "pass" if execution.result_bytes == expected else "fail"
            if invariant:
                rows.append(
                    {
                        "actual_result_ref": actual_ref,
                        "case_id": case["case_id"],
                        "expected_result_ref": case["expected_result_ref"],
                        "invariant_id": manifest[id_name],
                        "invariant_ref": validate_content_ref(manifest_ref),
                        "invariant_version": manifest[version_name],
                        "runner_profile_ref": manifest["runner_profile_ref"],
                        "verdict": verdict,
                    }
                )
            else:
                rows.append(
                    {
                        "actual_result_ref": actual_ref,
                        "case_id": case["case_id"],
                        "implementation_bundle_ref": validate_content_ref(bundle_ref),
                        "input_ref": case["input_ref"],
                        "expected_result_ref": case["expected_result_ref"],
                        "runner_profile_ref": manifest["runner_profile_ref"],
                        "suite_id": manifest[id_name],
                        "suite_ref": validate_content_ref(manifest_ref),
                        "suite_version": manifest[version_name],
                        "verdict": verdict,
                    }
                )
        return rows

    def build_report(
        self,
        *,
        candidate_genome: Mapping[str, Any],
        implementation_bundle: Mapping[str, Any],
        base_release: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        candidate = validate_genome(candidate_genome)
        base_genome = (
            None if base_release is None else validate_genome(base_release["genome"])
        )
        self._validate_genome_content(candidate)
        if base_genome is not None:
            self._validate_genome_content(base_genome)
        contract_delta, protocol_delta, monotonic = _genome_delta(
            base_genome, candidate
        )
        requirements = (
            candidate["compatibility_requirements"]
            if base_genome is None
            else base_genome["compatibility_requirements"]
        )
        self._validate_selected_execution(requirements)
        test_rows: list[dict[str, Any]] = []
        for item in requirements["required_suites"]:
            test_rows.extend(
                self._run_manifest(
                    item["suite_ref"], implementation_bundle, invariant=False
                )
            )
        invariant_rows: list[dict[str, Any]] = []
        for item in requirements["required_invariants"]:
            invariant_rows.extend(
                self._run_manifest(
                    item["invariant_ref"], implementation_bundle, invariant=True
                )
            )
        if len(test_rows) + len(invariant_rows) > MAX_EVIDENCE_ROWS:
            raise SpeciesError("compatibility_evidence_too_large")
        test_rows.sort(key=lambda item: _evidence_key(item, "compatibility-test"))
        invariant_rows.sort(key=lambda item: _evidence_key(item, "invariant"))
        passed = all(item["verdict"] == "pass" for item in test_rows + invariant_rows)
        verdict = (
            "genesis"
            if base_release is None and passed
            else "compatible"
            if monotonic and passed
            else "incompatible"
        )
        return {
            "base_release": None
            if base_release is None
            else {
                "artifact_hash": base_release["artifact_hash"],
                "artifact_id": base_release["artifact_id"],
                "epoch": base_release["position"]["epoch"],
                "sequence": base_release["position"]["sequence"],
            },
            "candidate_genome_hash": _entry_hash(candidate),
            "contract_delta": contract_delta,
            "invariant_evidence": _store_evidence_pages(
                self.cas, "invariant", invariant_rows
            ),
            "overall_verdict": verdict,
            "protocol_delta": protocol_delta,
            "schema": "daimon-species-compatibility-report/v0",
            "test_evidence": _store_evidence_pages(
                self.cas, "compatibility-test", test_rows
            ),
        }

    def verify_report(
        self,
        report: Mapping[str, Any],
        *,
        candidate_genome: Mapping[str, Any],
        implementation_bundle: Mapping[str, Any],
        base_release: Mapping[str, Any] | None,
        required_verdict: str,
    ) -> dict[str, Any]:
        supplied = validate_compatibility_report(report)
        recomputed = self.build_report(
            candidate_genome=candidate_genome,
            implementation_bundle=implementation_bundle,
            base_release=base_release,
        )
        if canonical_bytes(supplied) != canonical_bytes(recomputed):
            raise SpeciesError("compatibility_report_mismatch")
        if recomputed["overall_verdict"] != required_verdict:
            raise SpeciesError("compatibility_verdict_not_acceptable")
        _evidence_root(
            self.cas,
            recomputed["test_evidence"]["root_ref"],
            kind="compatibility-test",
            row_count=recomputed["test_evidence"]["row_count"],
        )
        _evidence_root(
            self.cas,
            recomputed["invariant_evidence"]["root_ref"],
            kind="invariant",
            row_count=recomputed["invariant_evidence"]["row_count"],
        )
        return recomputed

    def _required_suite_cases(
        self, genome: Mapping[str, Any]
    ) -> dict[tuple[str, str, str], dict[str, Any]]:
        cases: dict[tuple[str, str, str], dict[str, Any]] = {}
        for declared in genome["compatibility_requirements"]["required_suites"]:
            manifest = _suite_manifest(self.cas, declared["suite_ref"], invariant=False)
            if (
                manifest["suite_id"] != declared["suite_id"]
                or manifest["suite_version"] != declared["suite_version"]
            ):
                raise SpeciesError("required_suite_identity_mismatch")
            for case in manifest["cases"]:
                key = (
                    manifest["suite_id"],
                    manifest["suite_version"],
                    case["case_id"],
                )
                if key in cases:
                    raise SpeciesError("required_suite_case_duplicate")
                cases[key] = {
                    "case": case,
                    "runner_profile_ref": manifest["runner_profile_ref"],
                    "suite_ref": declared["suite_ref"],
                }
        return cases

    @staticmethod
    def _branch_delta(
        *,
        target: Mapping[str, Any],
        parent: Mapping[str, Any] | None,
        child: Mapping[str, Any] | None,
        reason: str,
    ) -> dict[str, Any]:
        marker = b64url(hashlib.sha256(canonical_bytes(target)).digest())[:24]
        return {
            "child_hash": None if child is None else _entry_hash(child),
            "delta_id": f"delta.{target['kind']}.{marker}",
            "parent_hash": None if parent is None else _entry_hash(parent),
            "reason_code": reason,
            "target": copy.deepcopy(dict(target)),
        }

    def build_breaking_delta(
        self,
        *,
        parent_genome: Mapping[str, Any],
        child_genome: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Derive the complete representable branch delta or fail closed."""

        parent = validate_genome(parent_genome)
        child = validate_genome(child_genome)
        self._validate_genome_content(parent)
        self._validate_genome_content(child)
        parent_requirements = parent["compatibility_requirements"]
        child_requirements = child["compatibility_requirements"]
        if canonical_bytes(parent["root_me_definition"]) != canonical_bytes(
            child["root_me_definition"]
        ):
            raise SpeciesError("branch_protected_root_change")
        if canonical_bytes(parent_requirements["resource_profile"]) != canonical_bytes(
            child_requirements["resource_profile"]
        ):
            raise SpeciesError("branch_protected_resource_profile_change")
        if not set(parent_requirements["forbidden_authority_changes"]) <= set(
            child_requirements["forbidden_authority_changes"]
        ):
            raise SpeciesError("branch_protected_authority_relaxation")

        def retained(name: str) -> bool:
            before = {canonical_bytes(item) for item in parent_requirements[name]}
            after = {canonical_bytes(item) for item in child_requirements[name]}
            return before <= after

        if not retained("required_invariants") or not {
            canonical_bytes(item) for item in parent["implementation_invariants"]
        } <= {canonical_bytes(item) for item in child["implementation_invariants"]}:
            raise SpeciesError("branch_protected_invariant_relaxation")

        deltas: list[dict[str, Any]] = []
        parent_contracts = {
            item["contract_id"]: item for item in parent["capability_contracts"]
        }
        child_contracts = {
            item["contract_id"]: item for item in child["capability_contracts"]
        }
        for identifier in sorted(set(parent_contracts) | set(child_contracts)):
            before = parent_contracts.get(identifier)
            after = child_contracts.get(identifier)
            if (
                before is not None
                and after is not None
                and canonical_bytes(before) == canonical_bytes(after)
            ):
                continue
            deltas.append(
                self._branch_delta(
                    target={"contract_id": identifier, "kind": "contract"},
                    parent=before,
                    child=after,
                    reason=(
                        "added-breaking"
                        if before is None
                        else "removed"
                        if after is None
                        else "changed-contract"
                    ),
                )
            )
        changed_contract_ids = {
            item["target"]["contract_id"]
            for item in deltas
            if item["target"]["kind"] == "contract"
        }
        if (
            set(parent_requirements["required_contract_ids"])
            ^ set(child_requirements["required_contract_ids"])
        ) - changed_contract_ids:
            raise SpeciesError("branch_unrepresented_required_contract_change")

        parent_protocols = {
            item["requirement_id"]: item for item in parent["protocol_requirements"]
        }
        child_protocols = {
            item["requirement_id"]: item for item in child["protocol_requirements"]
        }
        for identifier in sorted(set(parent_protocols) | set(child_protocols)):
            before = parent_protocols.get(identifier)
            after = child_protocols.get(identifier)
            if (
                before is not None
                and after is not None
                and canonical_bytes(before) == canonical_bytes(after)
            ):
                continue
            target = {"kind": "protocol", "requirement_id": identifier}
            parent_value = before
            child_value = after
            reason = (
                "added-breaking"
                if before is None
                else "removed"
                if after is None
                else "changed-protocol"
            )
            if before is not None and after is not None:
                before_without_bound = {
                    key: value for key, value in before.items() if key != "bounds_ref"
                }
                after_without_bound = {
                    key: value for key, value in after.items() if key != "bounds_ref"
                }
                if canonical_bytes(before_without_bound) == canonical_bytes(
                    after_without_bound
                ):
                    target = {"kind": "bound", "requirement_id": identifier}
                    parent_value = before["bounds_ref"]
                    child_value = after["bounds_ref"]
                    reason = "changed-bound"
            deltas.append(
                self._branch_delta(
                    target=target,
                    parent=parent_value,
                    child=child_value,
                    reason=reason,
                )
            )

        parent_cases = self._required_suite_cases(parent)
        child_cases = self._required_suite_cases(child)
        for key in sorted(set(parent_cases) | set(child_cases)):
            before_row = parent_cases.get(key)
            after_row = child_cases.get(key)
            before = None if before_row is None else before_row["case"]
            after = None if after_row is None else after_row["case"]
            if before is not None and after is not None:
                assert before_row is not None and after_row is not None
                for field in ("case_id", "entrypoint_id", "input_ref"):
                    if canonical_bytes(before[field]) != canonical_bytes(after[field]):
                        raise SpeciesError("branch_unrepresentable_suite_change")
                if canonical_bytes(before_row["runner_profile_ref"]) != canonical_bytes(
                    after_row["runner_profile_ref"]
                ):
                    raise SpeciesError("branch_unrepresentable_runner_change")
                if canonical_bytes(before["expected_result_ref"]) == canonical_bytes(
                    after["expected_result_ref"]
                ):
                    continue
            target = {
                "case_id": key[2],
                "kind": "required-output",
                "suite_id": key[0],
                "suite_version": key[1],
            }
            deltas.append(
                self._branch_delta(
                    target=target,
                    parent=None if before is None else before["expected_result_ref"],
                    child=None if after is None else after["expected_result_ref"],
                    reason=(
                        "added-breaking"
                        if before is None
                        else "removed"
                        if after is None
                        else "changed-required-output"
                    ),
                )
            )
        if not deltas:
            raise SpeciesError("branch_no_breaking_delta")
        deltas.sort(key=lambda item: item["delta_id"])
        if len(deltas) > MAX_SMALL_COLLECTION:
            raise SpeciesError("breaking_delta_too_large")
        return deltas

    def _branch_test_rows(
        self,
        *,
        parent_genome: Mapping[str, Any],
        child_implementation_bundle: Mapping[str, Any],
        delta_ids: Sequence[str],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for required in parent_genome["compatibility_requirements"]["required_suites"]:
            for result in self._run_manifest(
                required["suite_ref"], child_implementation_bundle, invariant=False
            ):
                differs = canonical_bytes(
                    result["actual_result_ref"]
                ) != canonical_bytes(result["expected_result_ref"])
                rows.append(
                    {
                        "actual_child_result_ref": result["actual_result_ref"],
                        "case_id": result["case_id"],
                        "child_implementation_bundle_ref": validate_content_ref(
                            child_implementation_bundle
                        ),
                        "delta_ids": list(delta_ids) if differs else [],
                        "expected_parent_result_ref": result["expected_result_ref"],
                        "input_ref": result["input_ref"],
                        "runner_profile_ref": result["runner_profile_ref"],
                        "suite_id": result["suite_id"],
                        "suite_ref": result["suite_ref"],
                        "suite_version": result["suite_version"],
                        "verdict": (
                            "incompatible-as-declared" if differs else "same-as-parent"
                        ),
                    }
                )
        rows.sort(key=lambda item: _evidence_key(item, "branch-test"))
        if not any(item["verdict"] == "incompatible-as-declared" for item in rows):
            raise SpeciesError("branch_no_observed_incompatibility")
        return rows

    def build_branch_report(
        self,
        *,
        parent_genome: Mapping[str, Any],
        child_genome: Mapping[str, Any],
        child_implementation_bundle: Mapping[str, Any],
        breaking_delta: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        parent = validate_genome(parent_genome)
        child = validate_genome(child_genome)
        expected_delta = self.build_breaking_delta(
            parent_genome=parent, child_genome=child
        )
        supplied = [copy.deepcopy(dict(item)) for item in breaking_delta]
        if canonical_bytes(supplied) != canonical_bytes(expected_delta):
            raise SpeciesError("breaking_delta_mismatch")
        for invariant in parent["compatibility_requirements"]["required_invariants"]:
            results = self._run_manifest(
                invariant["invariant_ref"],
                child_implementation_bundle,
                invariant=True,
            )
            if any(item["verdict"] != "pass" for item in results):
                raise SpeciesError("branch_protected_invariant_failure")
        self._validate_selected_execution(parent["compatibility_requirements"])
        delta_ids = [item["delta_id"] for item in expected_delta]
        rows = self._branch_test_rows(
            parent_genome=parent,
            child_implementation_bundle=child_implementation_bundle,
            delta_ids=delta_ids,
        )
        candidate = {
            "genome": child,
            "implementation_bundle": validate_content_ref(
                child_implementation_bundle,
                media_type=(
                    "application/vnd.daimon.species-implementation-bundle.v0+json"
                ),
            ),
        }
        return {
            "child_candidate_hash": _entry_hash(candidate),
            "overall_verdict": "deliberately-incompatible",
            "parent_requirements_hash": _entry_hash(
                parent["compatibility_requirements"]
            ),
            "test_evidence": _store_evidence_pages(self.cas, "branch-test", rows),
        }

    def verify_branch_foundation(
        self,
        foundation: Mapping[str, Any],
        *,
        parent_release: Mapping[str, Any],
    ) -> dict[str, Any]:
        checked = validate_branch_foundation(foundation)
        parent_genome = validate_genome(parent_release["genome"])
        expected_delta = self.build_breaking_delta(
            parent_genome=parent_genome,
            child_genome=checked["child_genome"],
        )
        supplied_by_target = {
            canonical_bytes(item["target"]): {
                key: value for key, value in item.items() if key != "delta_id"
            }
            for item in checked["breaking_delta"]
        }
        expected_by_target = {
            canonical_bytes(item["target"]): {
                key: value for key, value in item.items() if key != "delta_id"
            }
            for item in expected_delta
        }
        if supplied_by_target != expected_by_target:
            raise SpeciesError("breaking_delta_mismatch")
        expected_report = self.build_branch_report(
            parent_genome=parent_genome,
            child_genome=checked["child_genome"],
            child_implementation_bundle=checked["child_implementation_bundle"],
            breaking_delta=expected_delta,
        )
        supplied_report = checked["incompatibility_report"]
        if {
            key: supplied_report[key]
            for key in (
                "child_candidate_hash",
                "overall_verdict",
                "parent_requirements_hash",
            )
        } != {
            key: expected_report[key]
            for key in (
                "child_candidate_hash",
                "overall_verdict",
                "parent_requirements_hash",
            )
        }:
            raise SpeciesError("branch_report_mismatch")
        rows = _evidence_root(
            self.cas,
            supplied_report["test_evidence"]["root_ref"],
            kind="branch-test",
            row_count=supplied_report["test_evidence"]["row_count"],
        )
        expected_rows = _evidence_root(
            self.cas,
            expected_report["test_evidence"]["root_ref"],
            kind="branch-test",
            row_count=expected_report["test_evidence"]["row_count"],
        )
        known_ids = {item["delta_id"] for item in checked["breaking_delta"]}
        covered: set[str] = set()
        if len(rows) != len(expected_rows):
            raise SpeciesError("branch_test_evidence_mismatch")
        for supplied_row, expected_row in zip(rows, expected_rows, strict=True):
            validated = _closed(
                supplied_row,
                {
                    "actual_child_result_ref",
                    "case_id",
                    "child_implementation_bundle_ref",
                    "delta_ids",
                    "expected_parent_result_ref",
                    "input_ref",
                    "runner_profile_ref",
                    "suite_id",
                    "suite_ref",
                    "suite_version",
                    "verdict",
                },
                "branch_test_row_fields",
            )
            delta_ids = _sorted_unique_texts(validated["delta_ids"], "branch_delta_ids")
            if not set(delta_ids) <= known_ids:
                raise SpeciesError("branch_test_unknown_delta")
            differs = expected_row["verdict"] == "incompatible-as-declared"
            if (
                validated["verdict"] != expected_row["verdict"]
                or (differs and not delta_ids)
                or (not differs and delta_ids)
            ):
                raise SpeciesError("branch_test_verdict_mismatch")
            comparable = dict(validated)
            comparable["delta_ids"] = expected_row["delta_ids"]
            if canonical_bytes(comparable) != canonical_bytes(expected_row):
                raise SpeciesError("branch_test_evidence_mismatch")
            covered.update(delta_ids)
        if covered != known_ids:
            raise SpeciesError("branch_delta_not_covered")
        return checked


def _merge_artifacts(left: Mapping[str, Any], right: Mapping[str, Any]) -> Artifact:
    if (
        left.get("artifact_id") != right.get("artifact_id")
        or left.get("artifact_hash") != right.get("artifact_hash")
        or canonical_bytes(left.get("body")) != canonical_bytes(right.get("body"))
        or left.get("kind") != right.get("kind")
    ):
        raise SpeciesError("species_artifact_merge_conflict")
    signatures: dict[tuple[str, str], Mapping[str, Any]] = {}
    for artifact in (left, right):
        raw_signatures = artifact.get("signatures")
        if not isinstance(raw_signatures, list):
            raise SpeciesError("species_signature_invalid")
        for signature in raw_signatures:
            if not isinstance(signature, Mapping):
                raise SpeciesError("species_signature_invalid")
            marker = (str(signature.get("key_id")), str(signature.get("role")))
            existing = signatures.get(marker)
            if existing is not None and canonical_bytes(existing) != canonical_bytes(
                signature
            ):
                raise SpeciesError("species_signature_conflict")
            signatures[marker] = signature
    return _wrapper(
        str(left["kind"]),  # type: ignore[arg-type]
        left["body"],
        [signatures[key] for key in sorted(signatures)],
    )


def _release_reference(
    body: Mapping[str, Any], artifact_id: str, artifact_hash: str
) -> dict[str, Any]:
    return {
        "artifact_hash": artifact_hash,
        "artifact_id": artifact_id,
        "epoch": body["position"]["epoch"],
        "sequence": body["position"]["sequence"],
        "species_id": body["species_id"],
    }


class SpeciesRegistry:
    """Durable release positions, high-water, forks, previews, and applications."""

    def __init__(
        self,
        path: str | Path,
        cas: SpeciesCAS,
        *,
        forbidden_public_keys: Iterable[bytes] = (),
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self.cas = cas
        self.forbidden_public_keys = frozenset(forbidden_public_keys)
        self.compatibility = CompatibilityVerifier(cas)

    def _connect(self) -> sqlite3.Connection:
        _prepare_private_path(self.path)
        database = sqlite3.connect(
            self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None
        )
        database.row_factory = sqlite3.Row
        database.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        database.execute("PRAGMA foreign_keys=ON")
        mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
        if str(mode).lower() != "delete":
            database.close()
            raise SpeciesError("species_registry_journal_mode")
        database.execute("PRAGMA synchronous=FULL")
        return database

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        database = self._connect()
        try:
            yield database
        finally:
            database.close()

    @contextmanager
    def _exclusive_application_lock(self) -> Iterator[None]:
        """Serialize release evidence and pointer effects across processes."""

        lock_path = self.path.with_name(f"{self.path.name}.species.lock")
        _prepare_private_path(lock_path)
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise SpeciesError("species_application_lock_not_owner_only")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def initialize(self) -> None:
        self.cas.initialize()
        with self._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS species_state (
                    species_id TEXT PRIMARY KEY,
                    genesis_id TEXT NOT NULL,
                    genesis_hash TEXT NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('pending','active','quarantined')),
                    accepted_id TEXT,
                    accepted_hash TEXT,
                    accepted_epoch INTEGER,
                    accepted_sequence INTEGER,
                    greatest_epoch INTEGER,
                    greatest_sequence INTEGER,
                    closed_epoch INTEGER,
                    resolution_id TEXT
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS genesis_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL,
                    species_id TEXT NOT NULL,
                    artifact_json BLOB NOT NULL,
                    complete INTEGER NOT NULL CHECK(complete IN (0,1))
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS releases (
                    artifact_id TEXT PRIMARY KEY,
                    artifact_hash TEXT NOT NULL,
                    species_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    sequence INTEGER NOT NULL,
                    artifact_json BLOB NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('pending','accepted','quarantined','superseded')),
                    UNIQUE(species_id, epoch, sequence, artifact_id)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS release_positions
                    ON releases(species_id, epoch, sequence, artifact_id);
                CREATE TABLE IF NOT EXISTS snapshot_pages (
                    snapshot_hash TEXT NOT NULL,
                    page_index INTEGER NOT NULL,
                    snapshot_ref_json BLOB NOT NULL,
                    PRIMARY KEY(snapshot_hash, page_index)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS snapshot_material (
                    snapshot_hash TEXT PRIMARY KEY,
                    observed_ref_json BLOB NOT NULL,
                    evidence_refs_json BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS snapshot_sets (
                    page_set_hash TEXT NOT NULL,
                    page_index INTEGER NOT NULL,
                    snapshot_hash TEXT NOT NULL UNIQUE,
                    snapshot_ref_json BLOB NOT NULL,
                    PRIMARY KEY(page_set_hash, page_index)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS applications (
                    subject_me_id TEXT NOT NULL,
                    species_id TEXT NOT NULL,
                    application_sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_hash TEXT NOT NULL,
                    payload_json BLOB NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('accepted','quarantined')),
                    PRIMARY KEY(
                        subject_me_id, species_id, application_sequence, event_id
                    )
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS application_positions
                    ON applications(
                        subject_me_id, species_id, application_sequence, event_id
                    );
                CREATE TABLE IF NOT EXISTS application_journal (
                    operation_id TEXT PRIMARY KEY,
                    subject_me_id TEXT NOT NULL,
                    species_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('prepared','switched','event-appended','committed','rolled-back')),
                    prior_pointer BLOB,
                    target_pointer BLOB NOT NULL,
                    payload_json BLOB NOT NULL,
                    event_id TEXT
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS branch_relations (
                    child_species_id TEXT PRIMARY KEY,
                    parent_species_id TEXT NOT NULL,
                    parent_release_id TEXT NOT NULL,
                    foundation_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('accepted','quarantined'))
                ) WITHOUT ROWID;
                """
            )
        os.chmod(self.path, 0o600)

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
        try:
            value = json.loads(bytes(row["artifact_json"]))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SpeciesError("species_registry_corrupt") from error
        if not isinstance(value, Mapping):
            raise SpeciesError("species_registry_corrupt")
        return value

    def _validate_branch_origin(
        self, database: sqlite3.Connection, genesis: VerifiedGenesis
    ) -> dict[str, str] | None:
        origin = genesis.core["origin"]
        if origin["kind"] == "primordial":
            return None
        parent_ref = origin["parent_branch_release"]
        foundation = origin["branch_foundation"]
        assert parent_ref is not None and foundation is not None
        parent_row = self._release_row(database, parent_ref["artifact_id"])
        if parent_row is None:
            raise SpeciesError("branch_parent_release_missing", incomplete=True)
        expected_parent = {
            "artifact_hash": str(parent_row["artifact_hash"]),
            "artifact_id": str(parent_row["artifact_id"]),
            "epoch": int(parent_row["epoch"]),
            "sequence": int(parent_row["sequence"]),
        }
        if parent_ref != expected_parent:
            raise SpeciesError("branch_parent_release_mismatch")
        parent_body = validate_release_body(self._artifact_from_row(parent_row)["body"])
        if (
            parent_body["release_kind"] != "branch-declaration"
            or parent_row["state"] != "accepted"
            or canonical_bytes(parent_body["branch_declaration"])
            != canonical_bytes(foundation)
        ):
            raise SpeciesError("branch_parent_relation_not_accepted")
        if (
            canonical_bytes(genesis.core["genome"])
            != canonical_bytes(foundation["child_genome"])
            or canonical_bytes(genesis.core["initial_maintainers"])
            != canonical_bytes(foundation["child_initial_maintainers"])
            or canonical_bytes(genesis.core["maintainer_floor"])
            != canonical_bytes(foundation["child_maintainer_floor"])
            or genesis.core["species_nonce"] != foundation["child_species_nonce"]
        ):
            raise SpeciesError("branch_child_genesis_mismatch")
        return {
            "child_species_id": genesis.species_id,
            "foundation_hash": _entry_hash(foundation),
            "parent_release_id": parent_ref["artifact_id"],
            "parent_species_id": parent_body["species_id"],
        }

    def _refresh_branch_children(
        self, database: sqlite3.Connection, parent_species_id: str
    ) -> None:
        for relation in database.execute(
            "SELECT child_species_id, parent_release_id FROM branch_relations "
            "WHERE parent_species_id=? AND state='accepted'",
            (parent_species_id,),
        ):
            parent = self._release_row(database, str(relation["parent_release_id"]))
            if parent is not None and parent["state"] == "accepted":
                continue
            child = str(relation["child_species_id"])
            database.execute(
                "UPDATE branch_relations SET state='quarantined' "
                "WHERE child_species_id=?",
                (child,),
            )
            database.execute(
                "UPDATE species_state SET state='quarantined' WHERE species_id=?",
                (child,),
            )
            database.execute(
                "UPDATE releases SET state='quarantined' WHERE species_id=?",
                (child,),
            )

    def ingest_genesis(self, artifact: Mapping[str, Any]) -> dict[str, Any]:
        self.initialize()
        initial = verify_species_genesis(
            artifact, forbidden_public_keys=self.forbidden_public_keys
        )
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT artifact_json FROM genesis_artifacts WHERE artifact_id=?",
                    (initial.artifact_id,),
                ).fetchone()
                merged: Mapping[str, Any] = initial.artifact
                if existing is not None:
                    merged = _merge_artifacts(
                        self._artifact_from_row(existing), initial.artifact
                    )
                verified = verify_species_genesis(
                    merged, forbidden_public_keys=self.forbidden_public_keys
                )
                branch_relation = self._validate_branch_origin(database, verified)
                raw = canonical_bytes(merged)
                database.execute(
                    "INSERT INTO genesis_artifacts VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(artifact_id) DO UPDATE SET "
                    "artifact_json=excluded.artifact_json, "
                    "complete=excluded.complete",
                    (
                        verified.artifact_id,
                        verified.artifact_hash,
                        verified.species_id,
                        raw,
                        int(verified.complete),
                    ),
                )
                if branch_relation is not None:
                    existing_relation = database.execute(
                        "SELECT * FROM branch_relations WHERE child_species_id=?",
                        (verified.species_id,),
                    ).fetchone()
                    if existing_relation is not None and any(
                        str(existing_relation[field]) != branch_relation[field]
                        for field in (
                            "foundation_hash",
                            "parent_release_id",
                            "parent_species_id",
                        )
                    ):
                        raise SpeciesError("branch_relation_conflict")
                    database.execute(
                        "INSERT OR IGNORE INTO branch_relations VALUES (?, ?, ?, ?, "
                        "'accepted')",
                        (
                            branch_relation["child_species_id"],
                            branch_relation["parent_species_id"],
                            branch_relation["parent_release_id"],
                            branch_relation["foundation_hash"],
                        ),
                    )
                siblings = database.execute(
                    "SELECT artifact_id, complete FROM genesis_artifacts "
                    "WHERE species_id=? ORDER BY artifact_id",
                    (verified.species_id,),
                ).fetchall()
                complete_ids = [
                    str(item["artifact_id"]) for item in siblings if item["complete"]
                ]
                state = (
                    "quarantined"
                    if len(complete_ids) > 1
                    else "active"
                    if verified.complete
                    else "pending"
                )
                database.execute(
                    "INSERT INTO species_state "
                    "(species_id, genesis_id, genesis_hash, state) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(species_id) DO UPDATE SET state=excluded.state",
                    (
                        verified.species_id,
                        verified.artifact_id,
                        verified.artifact_hash,
                        state,
                    ),
                )
                if state == "quarantined":
                    database.execute(
                        "UPDATE releases SET state='quarantined' WHERE species_id=?",
                        (verified.species_id,),
                    )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "artifact_id": verified.artifact_id,
            "species_id": verified.species_id,
            "state": state,
        }

    def _genesis(
        self, database: sqlite3.Connection, species_id: str
    ) -> VerifiedGenesis:
        state = database.execute(
            "SELECT genesis_id, state FROM species_state WHERE species_id=?",
            (species_id,),
        ).fetchone()
        if state is None:
            raise SpeciesError("species_genesis_missing", incomplete=True)
        complete_genesis_count = int(
            database.execute(
                "SELECT COUNT(*) FROM genesis_artifacts "
                "WHERE species_id=? AND complete=1",
                (species_id,),
            ).fetchone()[0]
        )
        if complete_genesis_count > 1:
            raise SpeciesError("species_genesis_quarantined")
        row = database.execute(
            "SELECT artifact_json FROM genesis_artifacts WHERE artifact_id=?",
            (state["genesis_id"],),
        ).fetchone()
        if row is None:
            raise SpeciesError("species_registry_corrupt")
        genesis = verify_species_genesis(
            self._artifact_from_row(row),
            forbidden_public_keys=self.forbidden_public_keys,
        )
        if not genesis.complete:
            raise SpeciesError("species_genesis_pending", incomplete=True)
        return genesis

    def _release_row(
        self, database: sqlite3.Connection, artifact_id: str
    ) -> sqlite3.Row | None:
        row: sqlite3.Row | None = database.execute(
            "SELECT * FROM releases WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        return row

    def release(self, artifact_id: str) -> VerifiedRelease:
        self.initialize()
        _typed_id(artifact_id, _RELEASE_ID, "release_id")
        with self._database() as database:
            row = self._release_row(database, artifact_id)
            if row is None:
                raise SpeciesError("species_release_missing", incomplete=True)
            artifact = self._artifact_from_row(row)
            body = validate_release_body(artifact["body"])
            genesis = self._genesis(database, body["species_id"])
            if body["release_kind"] == "genesis":
                policy = genesis.core["initial_maintainers"]
                possession = False
            else:
                previous = body["previous_release"]
                if previous is None:
                    raise SpeciesError("release_predecessor_missing")
                predecessor_row = self._release_row(database, previous["artifact_id"])
                if predecessor_row is None:
                    raise SpeciesError("release_predecessor_missing", incomplete=True)
                predecessor = validate_release_body(
                    self._artifact_from_row(predecessor_row)["body"]
                )
                policy = predecessor["next_maintainers"]
                possession = (
                    canonical_bytes(policy) != canonical_bytes(body["next_maintainers"])
                    or body["release_kind"] == "fork-resolution"
                )
            return verify_species_release(
                artifact,
                authorizing_policy=policy,
                possession_required=possession,
                maintainer_floor=genesis.core["maintainer_floor"],
                forbidden_public_keys=self.forbidden_public_keys,
            )

    def birth_context(
        self,
        species_release_id: str,
        *,
        parent_enrollment_release_id: str | None = None,
    ) -> dict[str, Any]:
        """Classify DM-013 enrollment provenance without affecting identity."""

        self.initialize()
        try:
            offered_id = _typed_id(
                species_release_id, _RELEASE_ID, "birth_species_release_id"
            )
            parent_id = (
                None
                if parent_enrollment_release_id is None
                else _typed_id(
                    parent_enrollment_release_id,
                    _RELEASE_ID,
                    "birth_parent_enrollment_release_id",
                )
            )
        except SpeciesError:
            return {
                "reason_codes": ["malformed-release-id"],
                "release": None,
                "schema": "dm.species-birth-context/v0",
                "species_id": None,
                "state": "quarantined",
            }
        with self._database() as database:
            offered_row = self._release_row(database, offered_id)
            if offered_row is None:
                return {
                    "reason_codes": ["missing-release"],
                    "release": None,
                    "schema": "dm.species-birth-context/v0",
                    "species_id": None,
                    "state": "context-incomplete",
                }
            offered_body = validate_release_body(
                self._artifact_from_row(offered_row)["body"]
            )
            offered_ref = _release_reference(
                offered_body,
                str(offered_row["artifact_id"]),
                str(offered_row["artifact_hash"]),
            )
            lineage = offered_body["species_id"]
            lineage_state = database.execute(
                "SELECT * FROM species_state WHERE species_id=?", (lineage,)
            ).fetchone()
            if (
                offered_row["state"] in {"pending", "quarantined"}
                or lineage_state is None
                or lineage_state["state"] != "active"
            ):
                state = (
                    "context-incomplete"
                    if offered_row["state"] == "pending"
                    else "quarantined"
                )
                return {
                    "reason_codes": [
                        "pending-release" if state == "context-incomplete" else "fork"
                    ],
                    "release": offered_ref,
                    "schema": "dm.species-birth-context/v0",
                    "species_id": lineage,
                    "state": state,
                }
            accepted_id = lineage_state["accepted_id"]
            if accepted_id is None:
                return {
                    "reason_codes": ["missing-accepted-head"],
                    "release": offered_ref,
                    "schema": "dm.species-birth-context/v0",
                    "species_id": lineage,
                    "state": "context-incomplete",
                }
            try:
                self._path(database, offered_id, str(accepted_id))
            except SpeciesError:
                return {
                    "reason_codes": ["release-not-on-accepted-line"],
                    "release": offered_ref,
                    "schema": "dm.species-birth-context/v0",
                    "species_id": lineage,
                    "state": "quarantined",
                }
            if parent_id is not None:
                parent_row = self._release_row(database, parent_id)
                if parent_row is None:
                    return {
                        "reason_codes": ["missing-parent-enrollment"],
                        "release": offered_ref,
                        "schema": "dm.species-birth-context/v0",
                        "species_id": lineage,
                        "state": "context-incomplete",
                    }
                parent_body = validate_release_body(
                    self._artifact_from_row(parent_row)["body"]
                )
                if parent_body["species_id"] == lineage:
                    try:
                        self._path(database, parent_id, offered_id)
                    except SpeciesError:
                        return {
                            "reason_codes": ["below-enrollment-or-unrelated"],
                            "release": offered_ref,
                            "schema": "dm.species-birth-context/v0",
                            "species_id": lineage,
                            "state": "quarantined",
                        }
                else:
                    genesis = self._genesis(database, lineage)
                    origin = genesis.core["origin"]
                    foundation = origin["branch_foundation"]
                    declaration = origin["parent_branch_release"]
                    if (
                        origin["kind"] != "branch"
                        or foundation is None
                        or declaration is None
                        or foundation["parent_species_id"] != parent_body["species_id"]
                    ):
                        return {
                            "reason_codes": ["unrelated-lineage"],
                            "release": offered_ref,
                            "schema": "dm.species-birth-context/v0",
                            "species_id": lineage,
                            "state": "quarantined",
                        }
                    try:
                        self._path(database, parent_id, declaration["artifact_id"])
                    except SpeciesError:
                        return {
                            "reason_codes": ["unrelated-branch"],
                            "release": offered_ref,
                            "schema": "dm.species-birth-context/v0",
                            "species_id": lineage,
                            "state": "quarantined",
                        }
        return {
            "reason_codes": [],
            "release": offered_ref,
            "schema": "dm.species-birth-context/v0",
            "species_id": lineage,
            "state": "valid",
        }

    def _validate_release_relation(
        self,
        database: sqlite3.Connection,
        release: VerifiedRelease,
        genesis: VerifiedGenesis,
    ) -> tuple[Mapping[str, Any] | None, Mapping[str, Any], bool]:
        body = release.body
        if body["species_id"] != genesis.species_id or body["genesis"] != {
            "artifact_hash": genesis.artifact_hash,
            "artifact_id": genesis.artifact_id,
        }:
            raise SpeciesError("release_genesis_mismatch")
        kind = body["release_kind"]
        if kind == "genesis":
            if (
                body["position"] != {"epoch": 0, "sequence": 0}
                or body["previous_release"] is not None
                or canonical_bytes(body["genome"])
                != canonical_bytes(genesis.core["genome"])
                or canonical_bytes(body["next_maintainers"])
                != canonical_bytes(genesis.core["initial_maintainers"])
            ):
                raise SpeciesError("release_zero_mismatch")
            origin = genesis.core["origin"]
            if origin["kind"] == "branch":
                foundation = origin["branch_foundation"]
                assert foundation is not None
                if canonical_bytes(body["implementation_bundle"]) != canonical_bytes(
                    foundation["child_implementation_bundle"]
                ):
                    raise SpeciesError("branch_child_release_zero_bundle_mismatch")
            self.compatibility.verify_report(
                body["compatibility_report"],
                candidate_genome=body["genome"],
                implementation_bundle=body["implementation_bundle"],
                base_release=None,
                required_verdict="genesis",
            )
            return None, genesis.core["initial_maintainers"], False
        previous = body["previous_release"]
        if previous is None:
            raise SpeciesError("release_predecessor_missing")
        predecessor_row = self._release_row(database, previous["artifact_id"])
        if predecessor_row is None:
            raise SpeciesError("release_predecessor_missing", incomplete=True)
        predecessor_artifact = self._artifact_from_row(predecessor_row)
        predecessor_body = validate_release_body(predecessor_artifact["body"])
        expected_previous = {
            "artifact_hash": predecessor_row["artifact_hash"],
            "artifact_id": predecessor_row["artifact_id"],
            "epoch": predecessor_row["epoch"],
            "sequence": predecessor_row["sequence"],
        }
        if (
            previous != expected_previous
            or predecessor_body["species_id"] != body["species_id"]
        ):
            raise SpeciesError("release_predecessor_mismatch")
        if kind == "fork-resolution":
            resolution = body["fork_resolution"]
            assert resolution is not None
            if (
                predecessor_row["state"] != "accepted"
                or body["position"]
                != {"epoch": resolution["closed_epoch"] + 1, "sequence": 0}
                or resolution["common_predecessor"] != expected_previous
                or resolution["closure_cursor"]["epoch"] != resolution["closed_epoch"]
            ):
                raise SpeciesError("fork_resolution_position")
            self._validate_fork_closure(database, body)
        elif body["position"] != {
            "epoch": predecessor_body["position"]["epoch"],
            "sequence": predecessor_body["position"]["sequence"] + 1,
        }:
            raise SpeciesError("release_position_gap")
        if kind == "branch-declaration":
            foundation = body["branch_declaration"]
            assert foundation is not None
            parent_ref = _release_reference(
                predecessor_body,
                str(predecessor_row["artifact_id"]),
                str(predecessor_row["artifact_hash"]),
            )
            if (
                foundation["parent_base_release"] != parent_ref
                or canonical_bytes(body["genome"])
                != canonical_bytes(predecessor_body["genome"])
                or canonical_bytes(body["implementation_bundle"])
                != canonical_bytes(predecessor_body["implementation_bundle"])
                or canonical_bytes(body["next_maintainers"])
                != canonical_bytes(predecessor_body["next_maintainers"])
            ):
                raise SpeciesError("branch_declaration_parent_mismatch")
            self.compatibility.verify_branch_foundation(
                foundation,
                parent_release={
                    **predecessor_body,
                    "artifact_hash": predecessor_row["artifact_hash"],
                    "artifact_id": predecessor_row["artifact_id"],
                },
            )
        self.compatibility.verify_report(
            body["compatibility_report"],
            candidate_genome=body["genome"],
            implementation_bundle=body["implementation_bundle"],
            base_release={
                **predecessor_body,
                "artifact_hash": predecessor_row["artifact_hash"],
                "artifact_id": predecessor_row["artifact_id"],
            },
            required_verdict="compatible",
        )
        possession = (
            canonical_bytes(predecessor_body["next_maintainers"])
            != canonical_bytes(body["next_maintainers"])
            or kind == "fork-resolution"
        )
        return predecessor_body, predecessor_body["next_maintainers"], possession

    def _validate_fork_closure(
        self, database: sqlite3.Connection, body: Mapping[str, Any]
    ) -> None:
        resolution = body["fork_resolution"]
        root = _closed(
            _content_json(
                self.cas, resolution["closure_cursor"]["occupied_manifest_ref"]
            ),
            {
                "common_predecessor",
                "epoch",
                "occupied_count",
                "pages",
                "schema",
                "species_id",
            },
            "fork_closure_root_fields",
        )
        if (
            root["schema"] != "species-fork-closure-root/v0"
            or root["species_id"] != body["species_id"]
            or root["epoch"] != resolution["closed_epoch"]
            or root["common_predecessor"] != resolution["common_predecessor"]
            or root["occupied_count"] != resolution["closure_cursor"]["occupied_count"]
            or not isinstance(root["pages"], list)
        ):
            raise SpeciesError("fork_closure_root_mismatch")
        entries: list[Mapping[str, Any]] = []
        for index, raw_link in enumerate(root["pages"]):
            link = _closed(
                raw_link,
                {"entry_count", "first_key", "last_key", "page_index", "page_ref"},
                "fork_closure_link_fields",
            )
            if link["page_index"] != index or not 1 <= link["entry_count"] <= 256:
                raise SpeciesError("fork_closure_link")
            page = _closed(
                _content_json(self.cas, link["page_ref"]),
                {"entries", "page_index", "schema"},
                "fork_closure_page_fields",
            )
            if (
                page["schema"] != "species-fork-closure-page/v0"
                or page["page_index"] != index
                or not isinstance(page["entries"], list)
                or len(page["entries"]) != link["entry_count"]
            ):
                raise SpeciesError("fork_closure_page")
            checked_entries = []
            for raw_entry in page["entries"]:
                entry = _closed(
                    raw_entry,
                    {
                        "artifact_hash",
                        "artifact_id",
                        "epoch",
                        "previous_release",
                        "sequence",
                    },
                    "fork_closure_entry_fields",
                )
                checked_entries.append(
                    {
                        **_artifact_ref(
                            {
                                "artifact_hash": entry["artifact_hash"],
                                "artifact_id": entry["artifact_id"],
                            }
                        ),
                        "epoch": _uint(entry["epoch"], "fork_closure_position"),
                        "previous_release": None
                        if entry["previous_release"] is None
                        else _position_ref(entry["previous_release"]),
                        "sequence": _uint(entry["sequence"], "fork_closure_position"),
                    }
                )
            if any(
                item["epoch"] != resolution["closed_epoch"] for item in checked_entries
            ):
                raise SpeciesError("fork_closure_wrong_epoch")
            keys = [
                {
                    "artifact_id": item["artifact_id"],
                    "epoch": item["epoch"],
                    "sequence": item["sequence"],
                }
                for item in checked_entries
            ]
            if not keys or link["first_key"] != keys[0] or link["last_key"] != keys[-1]:
                raise SpeciesError("fork_closure_range")
            entries.extend(checked_entries)
        ordering = [
            (item["epoch"], item["sequence"], item["artifact_id"]) for item in entries
        ]
        if (
            len(entries) != root["occupied_count"]
            or ordering != sorted(set(ordering))
            or max(item["sequence"] for item in entries)
            != resolution["closure_cursor"]["max_sequence"]
        ):
            raise SpeciesError("fork_closure_entries")
        available = {
            str(row["artifact_id"]): row
            for row in database.execute(
                "SELECT artifact_id, artifact_hash, epoch, sequence, artifact_json "
                "FROM releases "
                "WHERE species_id=? AND epoch=?",
                (body["species_id"], resolution["closed_epoch"]),
            )
        }
        entry_by_id = {item["artifact_id"]: item for item in entries}
        common = resolution["common_predecessor"]
        position_counts: dict[tuple[int, int], int] = {}
        for item in entries:
            stored = available.get(item["artifact_id"])
            if stored is None:
                raise SpeciesError("fork_closure_missing_release", incomplete=True)
            stored_body = validate_release_body(self._artifact_from_row(stored)["body"])
            if (
                str(stored["artifact_hash"]) != item["artifact_hash"]
                or int(stored["epoch"]) != item["epoch"]
                or int(stored["sequence"]) != item["sequence"]
                or canonical_bytes(stored_body["previous_release"])
                != canonical_bytes(item["previous_release"])
            ):
                raise SpeciesError("fork_closure_release_mismatch")
            position = (item["epoch"], item["sequence"])
            position_counts[position] = position_counts.get(position, 0) + 1
            previous = item["previous_release"]
            if previous is None:
                raise SpeciesError("fork_closure_unreachable")
            if previous["artifact_id"] == common["artifact_id"]:
                if (
                    previous != common
                    or (
                        common["epoch"] == resolution["closed_epoch"]
                        and item["sequence"] <= common["sequence"]
                    )
                    or (
                        common["epoch"] < resolution["closed_epoch"]
                        and item["sequence"] != 0
                    )
                ):
                    raise SpeciesError("fork_closure_root")
            else:
                predecessor = entry_by_id.get(previous["artifact_id"])
                if (
                    predecessor is None
                    or previous
                    != {
                        "artifact_hash": predecessor["artifact_hash"],
                        "artifact_id": predecessor["artifact_id"],
                        "epoch": predecessor["epoch"],
                        "sequence": predecessor["sequence"],
                    }
                    or predecessor["sequence"] + 1 != item["sequence"]
                ):
                    raise SpeciesError("fork_closure_unreachable")
        if not any(count > 1 for count in position_counts.values()):
            raise SpeciesError("fork_resolution_unforked")
        heads = {
            (
                item["artifact_id"],
                item["artifact_hash"],
                item["epoch"],
                item["sequence"],
            )
            for item in resolution["competing_heads"]
        }
        referenced = {
            item["previous_release"]["artifact_id"]
            for item in entries
            if item["previous_release"] is not None
            and item["previous_release"]["artifact_id"]
            != resolution["common_predecessor"]["artifact_id"]
        }
        maximal = {
            (
                item["artifact_id"],
                item["artifact_hash"],
                item["epoch"],
                item["sequence"],
            )
            for item in entries
            if item["artifact_id"] not in referenced
        }
        if heads != maximal or len(heads) < 2:
            raise SpeciesError("fork_closure_heads")

    def ingest_release(self, artifact: Mapping[str, Any]) -> dict[str, Any]:
        with self._exclusive_application_lock():
            return self._ingest_release_locked(artifact)

    def _ingest_release_locked(self, artifact: Mapping[str, Any]) -> dict[str, Any]:
        self.initialize()
        raw_body, _, _ = _verify_wrapper(artifact, "release")
        candidate_body = validate_release_body(raw_body)
        species_id = candidate_body["species_id"]
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                genesis = self._genesis(database, species_id)
                existing = self._release_row(database, str(artifact["artifact_id"]))
                merged: Mapping[str, Any] = artifact
                if existing is not None:
                    merged = _merge_artifacts(
                        self._artifact_from_row(existing), artifact
                    )
                raw_body = merged["body"]
                candidate_body = validate_release_body(raw_body)
                predecessor, policy, possession = self._validate_release_relation(
                    database,
                    VerifiedRelease(
                        artifact=merged,
                        artifact_id=str(merged["artifact_id"]),
                        artifact_hash=str(merged["artifact_hash"]),
                        body=candidate_body,
                        complete=False,
                    ),
                    genesis,
                )
                verified = verify_species_release(
                    merged,
                    authorizing_policy=policy,
                    possession_required=possession,
                    maintainer_floor=genesis.core["maintainer_floor"],
                    forbidden_public_keys=self.forbidden_public_keys,
                )
                state = "pending"
                database.execute(
                    "INSERT INTO releases VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(artifact_id) DO UPDATE SET "
                    "artifact_json=excluded.artifact_json",
                    (
                        verified.artifact_id,
                        verified.artifact_hash,
                        species_id,
                        candidate_body["position"]["epoch"],
                        candidate_body["position"]["sequence"],
                        canonical_bytes(merged),
                        state,
                    ),
                )
                if (
                    verified.complete
                    and existing is not None
                    and existing["state"] != "pending"
                ):
                    state = str(existing["state"])
                elif verified.complete:
                    position = candidate_body["position"]
                    current = database.execute(
                        "SELECT * FROM species_state WHERE species_id=?",
                        (species_id,),
                    ).fetchone()
                    if current is None:
                        raise SpeciesError("species_registry_corrupt")
                    greatest = (position["epoch"], position["sequence"])
                    if current["greatest_epoch"] is not None:
                        greatest = max(
                            greatest,
                            (
                                int(current["greatest_epoch"]),
                                int(current["greatest_sequence"]),
                            ),
                        )
                    database.execute(
                        "UPDATE species_state SET greatest_epoch=?, "
                        "greatest_sequence=? WHERE species_id=?",
                        (greatest[0], greatest[1], species_id),
                    )
                    closed_high_water = (
                        None
                        if current["closed_epoch"] is None
                        else int(current["closed_epoch"])
                    )
                    predecessor_state = None
                    if candidate_body["previous_release"] is not None:
                        prior_row = self._release_row(
                            database,
                            candidate_body["previous_release"]["artifact_id"],
                        )
                        if prior_row is None:
                            raise SpeciesError("species_registry_corrupt")
                        predecessor_state = str(prior_row["state"])
                    old_closed_epoch = (
                        candidate_body["release_kind"] != "fork-resolution"
                        and closed_high_water is not None
                        and position["epoch"] <= closed_high_water
                    )
                    blocked_descendant = candidate_body[
                        "release_kind"
                    ] != "fork-resolution" and (
                        current["state"] == "quarantined"
                        or predecessor_state in {"quarantined", "superseded"}
                    )
                    if old_closed_epoch:
                        state = "superseded"
                        database.execute(
                            "UPDATE releases SET state='superseded' "
                            "WHERE artifact_id=?",
                            (verified.artifact_id,),
                        )
                    elif blocked_descendant:
                        state = "quarantined"
                        database.execute(
                            "UPDATE releases SET state='quarantined' "
                            "WHERE artifact_id=?",
                            (verified.artifact_id,),
                        )
                    else:
                        position_rows = database.execute(
                            "SELECT artifact_id FROM releases WHERE species_id=? "
                            "AND epoch=? "
                            "AND sequence=? AND state!='pending' ORDER BY artifact_id",
                            (species_id, position["epoch"], position["sequence"]),
                        ).fetchall()
                        sibling_ids = {
                            str(item["artifact_id"])
                            for item in position_rows
                            if item["artifact_id"] != verified.artifact_id
                        }
                        if sibling_ids:
                            state = "quarantined"
                            database.execute(
                                "UPDATE releases SET state='quarantined' "
                                "WHERE species_id=? "
                                "AND epoch=? AND sequence>=?",
                                (species_id, position["epoch"], position["sequence"]),
                            )
                            database.execute(
                                "UPDATE species_state SET state='quarantined', "
                                "accepted_id=?, accepted_hash=?, accepted_epoch=?, "
                                "accepted_sequence=? WHERE species_id=?",
                                (
                                    None
                                    if predecessor is None
                                    else candidate_body["previous_release"][
                                        "artifact_id"
                                    ],
                                    None
                                    if predecessor is None
                                    else candidate_body["previous_release"][
                                        "artifact_hash"
                                    ],
                                    None
                                    if predecessor is None
                                    else predecessor["position"]["epoch"],
                                    None
                                    if predecessor is None
                                    else predecessor["position"]["sequence"],
                                    species_id,
                                ),
                            )
                        else:
                            state = "accepted"
                            database.execute(
                                "UPDATE releases SET state='accepted' "
                                "WHERE artifact_id=?",
                                (verified.artifact_id,),
                            )
                            closed_epoch = (
                                candidate_body["fork_resolution"]["closed_epoch"]
                                if candidate_body["release_kind"] == "fork-resolution"
                                else None
                            )
                            database.execute(
                                "UPDATE species_state SET state='active', "
                                "accepted_id=?, accepted_hash=?, accepted_epoch=?, "
                                "accepted_sequence=?, greatest_epoch=?, "
                                "greatest_sequence=?, "
                                "closed_epoch=COALESCE(?,closed_epoch), "
                                "resolution_id=COALESCE(?,resolution_id) "
                                "WHERE species_id=?",
                                (
                                    verified.artifact_id,
                                    verified.artifact_hash,
                                    position["epoch"],
                                    position["sequence"],
                                    greatest[0],
                                    greatest[1],
                                    closed_epoch,
                                    verified.artifact_id
                                    if closed_epoch is not None
                                    else None,
                                    species_id,
                                ),
                            )
                            if closed_epoch is not None:
                                database.execute(
                                    "UPDATE releases SET state='superseded' "
                                    "WHERE species_id=? AND epoch=?",
                                    (species_id, closed_epoch),
                                )
                self._refresh_branch_children(database, species_id)
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "artifact_id": str(merged["artifact_id"]),
            "position": copy.deepcopy(candidate_body["position"]),
            "species_id": species_id,
            "state": state,
        }

    @staticmethod
    def _state_release_ref(state: sqlite3.Row) -> dict[str, Any] | None:
        if state["accepted_id"] is None:
            return None
        return {
            "artifact_hash": str(state["accepted_hash"]),
            "artifact_id": str(state["accepted_id"]),
            "epoch": int(state["accepted_epoch"]),
            "sequence": int(state["accepted_sequence"]),
            "species_id": str(state["species_id"]),
        }

    def _occupied(
        self, database: sqlite3.Connection, species_id: str
    ) -> list[dict[str, Any]]:
        return [
            {
                "artifact_hash": str(row["artifact_hash"]),
                "artifact_id": str(row["artifact_id"]),
                "epoch": int(row["epoch"]),
                "sequence": int(row["sequence"]),
                "species_id": species_id,
            }
            for row in database.execute(
                "SELECT artifact_id, artifact_hash, epoch, sequence FROM releases "
                "WHERE species_id=? AND state!='pending' "
                "ORDER BY epoch, sequence, artifact_id",
                (species_id,),
            )
        ]

    def _store_observed_positions(
        self, species_id: str, occupied: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        links: list[dict[str, Any]] = []
        for index, start in enumerate(range(0, len(occupied), MAX_POSITION_PAGE)):
            entries = [
                copy.deepcopy(dict(item))
                for item in occupied[start : start + MAX_POSITION_PAGE]
            ]
            page = {
                "entries": entries,
                "page_index": index,
                "schema": "species-observed-positions-page/v0",
            }
            page_ref = self.cas.put(
                canonical_bytes(page),
                "application/vnd.daimon.species-observed-positions-page.v0+json",
            )
            first = entries[0]
            last = entries[-1]
            links.append(
                {
                    "entry_count": len(entries),
                    "first_key": {
                        "artifact_id": first["artifact_id"],
                        "epoch": first["epoch"],
                        "sequence": first["sequence"],
                    },
                    "last_key": {
                        "artifact_id": last["artifact_id"],
                        "epoch": last["epoch"],
                        "sequence": last["sequence"],
                    },
                    "page_index": index,
                    "page_ref": page_ref,
                }
            )
        root = {
            "occupied_count": len(occupied),
            "pages": links,
            "schema": "species-observed-positions-root/v0",
            "species_id": species_id,
        }
        return self.cas.put(
            canonical_bytes(root),
            "application/vnd.daimon.species-observed-positions-root.v0+json",
        )

    @staticmethod
    def _content_refs(value: Any) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}

        def visit(item: Any) -> None:
            if isinstance(item, Mapping):
                if set(item) == {"byte_length", "content_id", "media_type", "sha256"}:
                    reference = validate_content_ref(item)
                    found[reference["content_id"]] = reference
                    return
                for child in item.values():
                    visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)

        visit(value)
        return [found[key] for key in sorted(found)]

    @staticmethod
    def _local_policy(value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {
                "allowed_species",
                "auto_apply",
                "policy_version",
                "resource_profile_ref",
                "schema",
            },
            "species_local_policy_fields",
        )
        if row[
            "schema"
        ] != "daimon-species-local-application-policy/v0" or not isinstance(
            row["auto_apply"], bool
        ):
            raise SpeciesError("species_local_policy")
        allowed = row["allowed_species"]
        if (
            not isinstance(allowed, list)
            or len(allowed) > MAX_SMALL_COLLECTION
            or allowed != sorted(set(allowed))
        ):
            raise SpeciesError("species_local_policy_allowlist")
        return {
            "allowed_species": [
                _typed_id(item, _SPECIES_ID, "species_local_policy_allowlist")
                for item in allowed
            ],
            "auto_apply": row["auto_apply"],
            "policy_version": _text(row["policy_version"], "species_policy_version"),
            "resource_profile_ref": validate_content_ref(row["resource_profile_ref"]),
            "schema": "daimon-species-local-application-policy/v0",
        }

    def store_local_policy(self, value: Mapping[str, Any]) -> dict[str, Any]:
        policy = self._local_policy(value)
        _resource_profile(self.cas, policy["resource_profile_ref"])
        return self.cas.put(
            canonical_bytes(policy),
            "application/vnd.daimon.daimon-species-local-application-policy.v0+json",
        )

    def load_local_policy(self, reference: Mapping[str, Any]) -> dict[str, Any]:
        policy = self._local_policy(_content_json(self.cas, reference))
        _resource_profile(self.cas, policy["resource_profile_ref"])
        return policy

    @staticmethod
    def _application_ref(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "application_sequence": int(row["application_sequence"]),
            "event_hash": str(row["event_hash"]),
            "event_id": str(row["event_id"]),
        }

    def _application_head(
        self, database: sqlite3.Connection, subject_me_id: str, species_id: str
    ) -> sqlite3.Row | None:
        row: sqlite3.Row | None = database.execute(
            "SELECT * FROM applications WHERE subject_me_id=? AND species_id=? "
            "AND state='accepted' ORDER BY application_sequence DESC LIMIT 1",
            (subject_me_id, species_id),
        ).fetchone()
        return row

    @staticmethod
    def _application_payload(row: sqlite3.Row) -> Mapping[str, Any]:
        try:
            value = json.loads(bytes(row["payload_json"]))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SpeciesError("species_application_corrupt") from error
        if not isinstance(value, Mapping):
            raise SpeciesError("species_application_corrupt")
        return value

    def _effective_release(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        payload = self._application_payload(row)
        result = payload.get("result")
        if result in {"applied", "rolled-back"}:
            return release_ref(payload["to_release"])
        from_release = payload.get("from_release")
        return None if from_release is None else release_ref(from_release)

    def _conflicts(
        self,
        database: sqlite3.Connection,
        species_id: str,
        subject_me_id: str | None = None,
    ) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []
        positions = database.execute(
            "SELECT epoch, sequence, COUNT(*) AS count FROM releases "
            "WHERE species_id=? AND state IN ('quarantined','superseded') "
            "GROUP BY epoch, sequence HAVING COUNT(*) > 1 ORDER BY epoch, sequence",
            (species_id,),
        ).fetchall()
        for position in positions:
            artifacts = [
                {
                    "artifact_hash": str(row["artifact_hash"]),
                    "artifact_id": str(row["artifact_id"]),
                }
                for row in database.execute(
                    "SELECT artifact_id, artifact_hash FROM releases "
                    "WHERE species_id=? "
                    "AND epoch=? AND sequence=? ORDER BY artifact_id",
                    (species_id, position["epoch"], position["sequence"]),
                )
            ]
            conflicts.append(
                {
                    "artifacts": artifacts,
                    "epoch": int(position["epoch"]),
                    "kind": "release-position",
                    "sequence": int(position["sequence"]),
                }
            )
        if subject_me_id is not None:
            positions = database.execute(
                "SELECT application_sequence, COUNT(*) AS count FROM applications "
                "WHERE subject_me_id=? AND species_id=? AND state='quarantined' "
                "GROUP BY application_sequence HAVING COUNT(*) > 1 "
                "ORDER BY application_sequence",
                (subject_me_id, species_id),
            ).fetchall()
            for position in positions:
                events = [
                    {
                        "event_hash": str(row["event_hash"]),
                        "event_id": str(row["event_id"]),
                    }
                    for row in database.execute(
                        "SELECT event_id, event_hash FROM applications "
                        "WHERE subject_me_id=? AND species_id=? "
                        "AND application_sequence=? ORDER BY event_id",
                        (
                            subject_me_id,
                            species_id,
                            position["application_sequence"],
                        ),
                    )
                ]
                conflicts.append(
                    {
                        "application_sequence": int(position["application_sequence"]),
                        "events": events,
                        "kind": "application-position",
                    }
                )
        conflicts.sort(key=lambda item: (str(item["kind"]), canonical_bytes(item)))
        return conflicts

    def _path(
        self,
        database: sqlite3.Connection,
        anchor_id: str,
        candidate_id: str,
    ) -> list[dict[str, Any]]:
        reversed_path: list[dict[str, Any]] = []
        current_id = candidate_id
        visited: set[str] = set()
        while current_id != anchor_id:
            if current_id in visited or len(visited) > MAX_SAFE_INTEGER:
                raise SpeciesError("species_release_cycle")
            visited.add(current_id)
            row = self._release_row(database, current_id)
            if row is None:
                raise SpeciesError("species_release_missing", incomplete=True)
            if row["state"] not in {"accepted", "superseded"}:
                raise SpeciesError("species_release_path_quarantined")
            artifact = self._artifact_from_row(row)
            body = validate_release_body(artifact["body"])
            reversed_path.append(
                _release_reference(
                    body, str(row["artifact_id"]), str(row["artifact_hash"])
                )
            )
            previous = body["previous_release"]
            if previous is None:
                raise SpeciesError("species_other_lineage")
            current_id = previous["artifact_id"]
        reversed_path.reverse()
        return reversed_path

    def incoming(
        self,
        *,
        subject_me_id: str,
        species_id: str,
        enrollment_release_id: str,
        selected_candidate_id: str | None = None,
        local_policy_ref: Mapping[str, Any] | None = None,
        page_index: int = 0,
        expected_occupied_positions_hash: str | None = None,
        authorized: bool = True,
    ) -> dict[str, Any]:
        """Return one read-only, cursor-bound page with no test or install effects."""

        if not authorized:
            return {"code": "not_authorized", "schema": "dm.species-denial/v0"}
        self.initialize()
        subject = _text(subject_me_id, "species_subject", maximum=240)
        lineage = _typed_id(species_id, _SPECIES_ID, "species_id")
        enrollment = _typed_id(
            enrollment_release_id, _RELEASE_ID, "enrollment_release_id"
        )
        page = _uint(page_index, "incoming_page_index")
        if page > 0 and expected_occupied_positions_hash is None:
            raise SpeciesError("incoming_page_cursor_required")
        with self._database() as database:
            state_row = database.execute(
                "SELECT * FROM species_state WHERE species_id=?", (lineage,)
            ).fetchone()
            occupied = self._occupied(database, lineage)
            occupied_hash = b64url(
                hashlib.sha256(
                    b"daimon/species-observed-positions/v0\x00"
                    + canonical_bytes(occupied)
                ).digest()
            )
            observed_ref = self._store_observed_positions(lineage, occupied)
            application_row = self._application_head(database, subject, lineage)
            application_head = (
                None
                if application_row is None
                else self._application_ref(application_row)
            )
            effective = self._effective_release(application_row)
            conflicts = self._conflicts(database, lineage, subject)
            reasons: set[str] = set()
            missing_refs: list[dict[str, Any]] = []
            candidate: dict[str, Any] | None = None
            selected_row: sqlite3.Row | None = None
            if selected_candidate_id is None and state_row is not None:
                selected_candidate_id = state_row["accepted_id"]
            if selected_candidate_id is not None:
                try:
                    _typed_id(selected_candidate_id, _RELEASE_ID, "selected_candidate")
                except SpeciesError:
                    reasons.add("invalid-selected")
                else:
                    selected_row = self._release_row(database, selected_candidate_id)
                    if selected_row is None:
                        reasons.add("missing-release")
                        missing_refs.append(
                            {
                                "kind": "release",
                                "release": {
                                    "artifact_hash": selected_candidate_id.rsplit(
                                        ":", 1
                                    )[1],
                                    "artifact_id": selected_candidate_id,
                                    "epoch": 0,
                                    "sequence": 0,
                                    "species_id": lineage,
                                },
                            }
                        )
                    else:
                        selected_body = validate_release_body(
                            self._artifact_from_row(selected_row)["body"]
                        )
                        candidate = _release_reference(
                            selected_body,
                            str(selected_row["artifact_id"]),
                            str(selected_row["artifact_hash"]),
                        )
                        if selected_body["species_id"] != lineage:
                            reasons.add("other-lineage")
            policy: Mapping[str, Any] | None = None
            if local_policy_ref is not None:
                policy = self._local_policy(_content_json(self.cas, local_policy_ref))
                _resource_profile(self.cas, policy["resource_profile_ref"])
                if not policy["auto_apply"] or lineage not in policy["allowed_species"]:
                    reasons.add("local-veto")
            elif candidate is not None:
                reasons.add("not-opted-in")
            if expected_occupied_positions_hash is not None and (
                _hash(expected_occupied_positions_hash, "occupied_positions_hash")
                != occupied_hash
            ):
                reasons.add("stale-cursor")
            if state_row is None or not occupied:
                reasons.add("missing-release")
            if state_row is not None and state_row["state"] == "quarantined":
                reasons.add("fork")
            if selected_row is not None and selected_row["state"] == "quarantined":
                reasons.add("fork")
            if any(item["kind"] == "application-position" for item in conflicts):
                reasons.add("application-fork")
            anchor_id = enrollment if effective is None else effective["artifact_id"]
            path: list[dict[str, Any]] = []
            if candidate is not None and not (
                {"fork", "invalid-selected", "other-lineage"} & reasons
            ):
                try:
                    path = self._path(database, anchor_id, candidate["artifact_id"])
                except SpeciesError as error:
                    if error.incomplete:
                        reasons.add("missing-release")
                    elif error.code == "species_other_lineage":
                        reasons.add("other-lineage")
                    else:
                        reasons.add("fork")
            start_offset = page * MAX_INCOMING_PAGE
            if start_offset > len(path) or (page > 0 and start_offset >= len(path)):
                raise SpeciesError("incoming_page_out_of_range")
            page_releases = path[start_offset : start_offset + MAX_INCOMING_PAGE]
            continuation = (
                path[start_offset + MAX_INCOMING_PAGE]
                if start_offset + MAX_INCOMING_PAGE < len(path)
                else None
            )
            if continuation is not None:
                reasons.add("path-continues")
            if page == 0 and effective is not None:
                start_release = effective
            elif page == 0:
                try:
                    start_release = self._release_ref_for_id(database, enrollment)
                except SpeciesError as error:
                    if not error.incomplete:
                        raise
                    start_release = None
            else:
                start_release = path[start_offset - 1]
            end_release = page_releases[-1] if page_releases else start_release
            evidence_refs: dict[str, dict[str, Any]] = {}
            for item in path:
                release_row = self._release_row(database, item["artifact_id"])
                if release_row is None:
                    continue
                artifact = self._artifact_from_row(release_row)
                for reference in self._content_refs(artifact["body"]):
                    if self.cas.has(reference):
                        evidence_refs[reference["content_id"]] = reference
                    else:
                        reasons.add("missing-content")
                        missing_refs.append({"content": reference, "kind": "content"})
            evidence = [evidence_refs[key] for key in sorted(evidence_refs)]
            evidence_hash = b64url(
                hashlib.sha256(
                    b"daimon/species-evidence-closure/v0\x00"
                    + canonical_bytes(evidence)
                ).digest()
            )
            if conflicts or "fork" in reasons or "invalid-selected" in reasons:
                projection_state = "quarantined"
            elif {
                "missing-content",
                "missing-release",
                "stale-cursor",
            } & reasons:
                projection_state = "incomplete"
            elif "other-lineage" in reasons:
                projection_state = "diverged"
            elif effective is None:
                projection_state = "incomplete"
                reasons.add("unmanifested-runtime")
            elif (
                candidate is not None
                and effective["artifact_id"] == candidate["artifact_id"]
            ):
                projection_state = "current"
            else:
                projection_state = "compatible-behind"
            opted_in = (
                policy is not None
                and policy["auto_apply"] is True
                and lineage in policy["allowed_species"]
            )
            eligible = (
                projection_state == "compatible-behind"
                and continuation is None
                and opted_in
                and not conflicts
            ) or (
                effective is None
                and candidate is not None
                and candidate["artifact_id"] == enrollment
                and reasons <= {"unmanifested-runtime"}
                and opted_in
            )
            cursor = {
                "accepted_head": None
                if state_row is None
                else self._state_release_ref(state_row),
                "closed_epoch_high_water": None
                if state_row is None or state_row["closed_epoch"] is None
                else {
                    "closed_epoch": int(state_row["closed_epoch"]),
                    "resolution_release": self._release_ref_for_id(
                        database, str(state_row["resolution_id"])
                    ),
                },
                "greatest_observed": None
                if state_row is None or state_row["greatest_epoch"] is None
                else {
                    "epoch": int(state_row["greatest_epoch"]),
                    "sequence": int(state_row["greatest_sequence"]),
                },
                "occupied_positions_hash": occupied_hash,
            }
            snapshot_core = {
                "application_eligible": eligible,
                "application_head": application_head,
                "conflict_refs": conflicts,
                "effective_applied_release": effective,
                "enrollment_release_id": enrollment,
                "evidence_closure_hash": evidence_hash,
                "missing_refs": sorted(
                    missing_refs,
                    key=lambda item: (str(item["kind"]), canonical_bytes(item)),
                ),
                "path_page": {
                    "continuation_release": continuation,
                    "end_release": end_release,
                    "page_index": page,
                    "releases": page_releases,
                    "start_release": start_release,
                },
                "reason_codes": sorted(reasons),
                "registry_cursor": cursor,
                "selected_candidate": candidate,
                "species_id": lineage,
                "state": projection_state,
                "subject_me_id": subject,
            }
            snapshot_hash = b64url(
                hashlib.sha256(
                    b"daimon/species-incoming-snapshot/v0\x00"
                    + canonical_bytes(snapshot_core)
                ).digest()
            )
            result = {
                "schema": INCOMING_SCHEMA,
                "snapshot_core": snapshot_core,
                "snapshot_hash": snapshot_hash,
            }
            page_set_binding = {
                "application_head": application_head,
                "conflict_refs": conflicts,
                "effective_applied_release": effective,
                "enrollment_release_id": enrollment,
                "evidence_closure_hash": evidence_hash,
                "missing_refs": snapshot_core["missing_refs"],
                "reason_codes": sorted(reasons - {"path-continues"}),
                "registry_cursor": cursor,
                "selected_candidate": candidate,
                "species_id": lineage,
                "state": projection_state,
                "subject_me_id": subject,
            }
            page_set_hash = b64url(
                hashlib.sha256(
                    b"daimon/species-incoming-page-set/v0\x00"
                    + canonical_bytes(page_set_binding)
                ).digest()
            )
            snapshot_ref = self.cas.put(
                canonical_bytes(result),
                "application/vnd.daimon.daimon-species-incoming-result.v0+json",
            )
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "INSERT OR REPLACE INTO snapshot_pages VALUES (?, ?, ?)",
                    (snapshot_hash, page, canonical_bytes(snapshot_ref)),
                )
                database.execute(
                    "INSERT OR REPLACE INTO snapshot_material VALUES (?, ?, ?)",
                    (
                        snapshot_hash,
                        canonical_bytes(observed_ref),
                        canonical_bytes(evidence),
                    ),
                )
                existing_set_page = database.execute(
                    "SELECT snapshot_hash, snapshot_ref_json FROM snapshot_sets "
                    "WHERE page_set_hash=? AND page_index=?",
                    (page_set_hash, page),
                ).fetchone()
                if existing_set_page is not None and (
                    existing_set_page["snapshot_hash"] != snapshot_hash
                    or bytes(existing_set_page["snapshot_ref_json"])
                    != canonical_bytes(snapshot_ref)
                ):
                    raise SpeciesError("incoming_page_set_conflict")
                database.execute(
                    "INSERT OR IGNORE INTO snapshot_sets VALUES (?, ?, ?, ?)",
                    (
                        page_set_hash,
                        page,
                        snapshot_hash,
                        canonical_bytes(snapshot_ref),
                    ),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return result

    def _release_ref_for_id(
        self, database: sqlite3.Connection, artifact_id: str
    ) -> dict[str, Any]:
        row = self._release_row(database, artifact_id)
        if row is None:
            raise SpeciesError("species_release_missing", incomplete=True)
        body = validate_release_body(self._artifact_from_row(row)["body"])
        return _release_reference(
            body, str(row["artifact_id"]), str(row["artifact_hash"])
        )

    @staticmethod
    def _runtime_manifest(value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {
                "capability_grant_set_hash",
                "code_config_pointer_digest",
                "implementation_bundle_ref",
                "release",
                "schema",
            },
            "species_runtime_manifest_fields",
        )
        bundle = validate_content_ref(row["implementation_bundle_ref"])
        pointer_digest = _hash(
            row["code_config_pointer_digest"], "code_config_pointer_digest"
        )
        if pointer_digest != bundle["sha256"]:
            raise SpeciesError("runtime_pointer_digest_mismatch")
        return {
            "capability_grant_set_hash": _hash(
                row["capability_grant_set_hash"], "capability_grant_set_hash"
            ),
            "code_config_pointer_digest": pointer_digest,
            "implementation_bundle_ref": bundle,
            "release": release_ref(row["release"]),
            "schema": "species-runtime-manifest/v0",
        }

    def _verification_manifest(self, value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {
                "enrollment_release_id",
                "forward",
                "from_release",
                "implementation_bundle_ref",
                "mode",
                "rollback",
                "schema",
                "species_id",
                "subject_me_id",
                "to_release",
            },
            "species_verification_manifest_fields",
        )
        mode = row["mode"]
        if mode not in {"bootstrap", "forward", "rollback"}:
            raise SpeciesError("species_verification_mode")
        if (mode == "rollback") != (row["rollback"] is not None) or (
            mode == "rollback"
        ) == (row["forward"] is not None):
            raise SpeciesError("species_verification_mode_payload")
        forward = None
        if row["forward"] is not None:
            forward_row = _closed(
                row["forward"],
                {
                    "evidence_refs",
                    "observed_positions_manifest_ref",
                    "snapshot_page_refs",
                },
                "species_verification_forward_fields",
            )
            pages = forward_row["snapshot_page_refs"]
            if not isinstance(pages, list) or not pages:
                raise SpeciesError("species_verification_pages")
            page_refs = [validate_content_ref(item) for item in pages]
            evidence = forward_row["evidence_refs"]
            if not isinstance(evidence, list):
                raise SpeciesError("species_verification_evidence")
            evidence_refs = [validate_content_ref(item) for item in evidence]
            ids = [item["content_id"] for item in evidence_refs]
            if ids != sorted(set(ids)):
                raise SpeciesError("species_verification_evidence")
            forward = {
                "evidence_refs": evidence_refs,
                "observed_positions_manifest_ref": validate_content_ref(
                    forward_row["observed_positions_manifest_ref"]
                ),
                "snapshot_page_refs": page_refs,
            }
        rollback = None
        if row["rollback"] is not None:
            rollback_row = _closed(
                row["rollback"],
                {
                    "current_application",
                    "current_snapshot_ref",
                    "observed_positions_manifest_ref",
                    "reason",
                    "target_application",
                    "target_runtime_manifest_ref",
                },
                "species_verification_rollback_fields",
            )
            if rollback_row["reason"] not in {"release-fork", "runtime-failure"}:
                raise SpeciesError("species_rollback_reason")
            rollback = {
                "current_application": self._validate_application_ref(
                    rollback_row["current_application"]
                ),
                "current_snapshot_ref": validate_content_ref(
                    rollback_row["current_snapshot_ref"]
                ),
                "observed_positions_manifest_ref": validate_content_ref(
                    rollback_row["observed_positions_manifest_ref"]
                ),
                "reason": rollback_row["reason"],
                "target_application": self._validate_application_ref(
                    rollback_row["target_application"]
                ),
                "target_runtime_manifest_ref": validate_content_ref(
                    rollback_row["target_runtime_manifest_ref"]
                ),
            }
        return {
            "enrollment_release_id": _typed_id(
                row["enrollment_release_id"], _RELEASE_ID, "enrollment_release_id"
            ),
            "forward": forward,
            "from_release": None
            if row["from_release"] is None
            else release_ref(row["from_release"]),
            "implementation_bundle_ref": validate_content_ref(
                row["implementation_bundle_ref"]
            ),
            "mode": mode,
            "rollback": rollback,
            "schema": "species-application-verification/v0",
            "species_id": _typed_id(row["species_id"], _SPECIES_ID, "species_id"),
            "subject_me_id": _text(
                row["subject_me_id"], "species_subject", maximum=240
            ),
            "to_release": release_ref(row["to_release"]),
        }

    @staticmethod
    def _validate_application_ref(value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {"application_sequence", "event_hash", "event_id"},
            "species_application_ref_fields",
        )
        try:
            event_id = str(uuid.UUID(str(row["event_id"])))
        except ValueError as error:
            raise SpeciesError("species_application_event_id") from error
        event_hash = row["event_hash"]
        if (
            not isinstance(event_hash, str)
            or len(event_hash) != 64
            or any(character not in "0123456789abcdef" for character in event_hash)
        ):
            raise SpeciesError("species_application_event_hash")
        return {
            "application_sequence": _uint(
                row["application_sequence"], "species_application_sequence"
            ),
            "event_hash": event_hash,
            "event_id": event_id,
        }

    @classmethod
    def validate_application_payload(cls, value: Any) -> dict[str, Any]:
        row = _closed(
            value,
            {
                "application_sequence",
                "applied_at_ms",
                "enrollment_release_id",
                "from_release",
                "implementation_bundle_ref",
                "local_policy_ref",
                "previous_application",
                "prior_runtime_manifest_ref",
                "result",
                "resulting_runtime_manifest_ref",
                "schema",
                "species_id",
                "subject_me_id",
                "to_release",
                "verification_manifest_ref",
            },
            "species_application_fields",
        )
        if row["schema"] != APPLICATION_SCHEMA or row["result"] not in {
            "applied",
            "failed",
            "rolled-back",
            "vetoed",
        }:
            raise SpeciesError("species_application_schema_result")
        result = {
            "application_sequence": _uint(
                row["application_sequence"], "species_application_sequence"
            ),
            "applied_at_ms": _uint(row["applied_at_ms"], "species_applied_at"),
            "enrollment_release_id": _typed_id(
                row["enrollment_release_id"], _RELEASE_ID, "enrollment_release_id"
            ),
            "from_release": None
            if row["from_release"] is None
            else release_ref(row["from_release"]),
            "implementation_bundle_ref": validate_content_ref(
                row["implementation_bundle_ref"]
            ),
            "local_policy_ref": validate_content_ref(row["local_policy_ref"]),
            "previous_application": None
            if row["previous_application"] is None
            else cls._validate_application_ref(row["previous_application"]),
            "prior_runtime_manifest_ref": None
            if row["prior_runtime_manifest_ref"] is None
            else validate_content_ref(row["prior_runtime_manifest_ref"]),
            "result": row["result"],
            "resulting_runtime_manifest_ref": None
            if row["resulting_runtime_manifest_ref"] is None
            else validate_content_ref(row["resulting_runtime_manifest_ref"]),
            "schema": APPLICATION_SCHEMA,
            "species_id": _typed_id(row["species_id"], _SPECIES_ID, "species_id"),
            "subject_me_id": _text(
                row["subject_me_id"], "species_subject", maximum=240
            ),
            "to_release": release_ref(row["to_release"]),
            "verification_manifest_ref": validate_content_ref(
                row["verification_manifest_ref"]
            ),
        }
        sequence = result["application_sequence"]
        previous = result["previous_application"]
        if (sequence == 0) != (previous is None) or (
            previous is not None and previous["application_sequence"] + 1 != sequence
        ):
            raise SpeciesError("species_application_predecessor")
        if result["to_release"]["species_id"] != result["species_id"]:
            raise SpeciesError("species_application_lineage")
        if result["result"] in {"vetoed", "failed"} and canonical_bytes(
            result["prior_runtime_manifest_ref"]
        ) != canonical_bytes(result["resulting_runtime_manifest_ref"]):
            raise SpeciesError("species_application_failed_runtime_changed")
        return result

    @staticmethod
    def _atomic_pointer(path: Path, raw: bytes) -> None:
        parent = path.parent
        _prepare_private_path(parent, directory=True)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise SpeciesError("species_pointer_not_owner_only")
        staged = parent / f".species-pointer-{uuid.uuid4()}"
        descriptor = os.open(
            staged,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            if os.write(descriptor, raw) != len(raw):
                raise SpeciesError("species_pointer_write_short")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(staged, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _validate_application_transition(
        self, database: sqlite3.Connection, payload: Mapping[str, Any]
    ) -> None:
        lineage = payload["species_id"]
        enrollment_row = self._release_row(database, payload["enrollment_release_id"])
        target_row = self._release_row(database, payload["to_release"]["artifact_id"])
        if enrollment_row is None or target_row is None:
            raise SpeciesError("species_application_release_missing", incomplete=True)
        enrollment_body = validate_release_body(
            self._artifact_from_row(enrollment_row)["body"]
        )
        target_body = validate_release_body(self._artifact_from_row(target_row)["body"])
        target_ref = _release_reference(
            target_body,
            str(target_row["artifact_id"]),
            str(target_row["artifact_hash"]),
        )
        if (
            enrollment_body["species_id"] != lineage
            or target_body["species_id"] != lineage
            or target_ref != payload["to_release"]
            or canonical_bytes(target_body["implementation_bundle"])
            != canonical_bytes(payload["implementation_bundle_ref"])
        ):
            raise SpeciesError("species_application_release_mismatch")
        previous_ref = payload["previous_application"]
        previous_row: sqlite3.Row | None = None
        previous_effective: dict[str, Any] | None = None
        previous_runtime_ref: Mapping[str, Any] | None = None
        if previous_ref is not None:
            previous_row = database.execute(
                "SELECT * FROM applications WHERE event_id=?",
                (previous_ref["event_id"],),
            ).fetchone()
            if previous_row is None:
                raise SpeciesError(
                    "species_application_predecessor_missing", incomplete=True
                )
            if self._application_ref(previous_row) != previous_ref:
                raise SpeciesError("species_application_predecessor_mismatch")
            previous_payload = self.validate_application_payload(
                self._application_payload(previous_row)
            )
            if (
                previous_payload["subject_me_id"] != payload["subject_me_id"]
                or previous_payload["species_id"] != lineage
                or previous_payload["enrollment_release_id"]
                != payload["enrollment_release_id"]
            ):
                raise SpeciesError("species_application_chain_mismatch")
            previous_effective = self._effective_release(previous_row)
            previous_runtime_ref = previous_payload["resulting_runtime_manifest_ref"]
        if payload["from_release"] != previous_effective or canonical_bytes(
            payload["prior_runtime_manifest_ref"]
        ) != canonical_bytes(previous_runtime_ref):
            raise SpeciesError("species_application_effective_predecessor")

        verification = self._verification_manifest(
            _content_json(self.cas, payload["verification_manifest_ref"])
        )
        if (
            verification["subject_me_id"] != payload["subject_me_id"]
            or verification["species_id"] != lineage
            or verification["enrollment_release_id"] != payload["enrollment_release_id"]
            or verification["from_release"] != payload["from_release"]
            or verification["to_release"] != payload["to_release"]
            or canonical_bytes(verification["implementation_bundle_ref"])
            != canonical_bytes(payload["implementation_bundle_ref"])
        ):
            raise SpeciesError("species_application_verification_mismatch")
        result = payload["result"]
        if result == "applied":
            expected_mode = (
                "bootstrap" if payload["application_sequence"] == 0 else "forward"
            )
            if verification["mode"] != expected_mode or (
                expected_mode == "bootstrap"
                and payload["to_release"]["artifact_id"]
                != payload["enrollment_release_id"]
            ):
                raise SpeciesError("species_application_mode_mismatch")
        elif result == "rolled-back" and verification["mode"] != "rollback":
            raise SpeciesError("species_application_mode_mismatch")
        resulting_ref = payload["resulting_runtime_manifest_ref"]
        if resulting_ref is not None:
            resulting_runtime = self._runtime_manifest(
                _content_json(self.cas, resulting_ref)
            )
            if resulting_runtime["release"] != payload["to_release"] or canonical_bytes(
                resulting_runtime["implementation_bundle_ref"]
            ) != canonical_bytes(payload["implementation_bundle_ref"]):
                raise SpeciesError("species_application_runtime_mismatch")

    def record_application_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Persist one already DM-011-verified operational application event."""

        self.initialize()
        if (
            event.get("kind") != APPLICATION_EVENT_KIND
            or event.get("subject") != event.get("being_ref")
            or not isinstance(event.get("payload"), Mapping)
        ):
            raise SpeciesError("species_application_event_binding")
        payload = self.validate_application_payload(event["payload"])
        if payload["subject_me_id"] != event["subject"]:
            raise SpeciesError("species_application_event_binding")
        event_ref = self._validate_application_ref(
            {
                "application_sequence": payload["application_sequence"],
                "event_hash": event.get("content_hash"),
                "event_id": event.get("event_id"),
            }
        )
        previous = payload["previous_application"]
        parents = event.get("causal_parents")
        if not isinstance(parents, list) or (
            previous is not None and previous["event_id"] not in parents
        ):
            raise SpeciesError("species_application_event_causality")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                self._validate_application_transition(database, payload)
                existing = database.execute(
                    "SELECT payload_json, event_hash, state FROM applications "
                    "WHERE event_id=?",
                    (event_ref["event_id"],),
                ).fetchone()
                raw_payload = canonical_bytes(payload)
                if existing is not None:
                    if (
                        bytes(existing["payload_json"]) != raw_payload
                        or existing["event_hash"] != event_ref["event_hash"]
                    ):
                        raise SpeciesError("species_application_event_conflict")
                    state = str(existing["state"])
                else:
                    siblings = database.execute(
                        "SELECT event_id FROM applications WHERE subject_me_id=? "
                        "AND species_id=? AND application_sequence=?",
                        (
                            payload["subject_me_id"],
                            payload["species_id"],
                            payload["application_sequence"],
                        ),
                    ).fetchall()
                    state = "quarantined" if siblings else "accepted"
                    database.execute(
                        "INSERT INTO applications VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            payload["subject_me_id"],
                            payload["species_id"],
                            payload["application_sequence"],
                            event_ref["event_id"],
                            event_ref["event_hash"],
                            raw_payload,
                            state,
                        ),
                    )
                    if siblings:
                        database.execute(
                            "UPDATE applications SET state='quarantined' "
                            "WHERE subject_me_id=? AND species_id=? "
                            "AND application_sequence>=?",
                            (
                                payload["subject_me_id"],
                                payload["species_id"],
                                payload["application_sequence"],
                            ),
                        )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {**event_ref, "state": state}

    def apply(
        self,
        *,
        operation_id: str,
        snapshot: Mapping[str, Any],
        local_policy_ref: Mapping[str, Any],
        capability_grant_set_hash: str,
        pointer_path: str | Path,
        applied_at_ms: int,
        append_event: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        with self._exclusive_application_lock():
            return self._apply_locked(
                operation_id=operation_id,
                snapshot=snapshot,
                local_policy_ref=local_policy_ref,
                capability_grant_set_hash=capability_grant_set_hash,
                pointer_path=pointer_path,
                applied_at_ms=applied_at_ms,
                append_event=append_event,
                fault_hook=fault_hook,
            )

    def _apply_locked(
        self,
        *,
        operation_id: str,
        snapshot: Mapping[str, Any],
        local_policy_ref: Mapping[str, Any],
        capability_grant_set_hash: str,
        pointer_path: str | Path,
        applied_at_ms: int,
        append_event: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Switch exact verified bytes and append one canonical event crash-safely."""

        self.initialize()
        try:
            operation = str(uuid.UUID(operation_id))
        except ValueError as error:
            raise SpeciesError("species_operation_id") from error
        expected_event_id = str(
            uuid.uuid5(uuid.UUID(operation), APPLICATION_EVENT_KIND)
        )
        snapshot_row = _closed(
            snapshot, {"schema", "snapshot_core", "snapshot_hash"}, "incoming_fields"
        )
        if snapshot_row["schema"] != INCOMING_SCHEMA:
            raise SpeciesError("incoming_schema")
        core = snapshot_row["snapshot_core"]
        if not isinstance(core, Mapping):
            raise SpeciesError("incoming_core")
        expected_hash = b64url(
            hashlib.sha256(
                b"daimon/species-incoming-snapshot/v0\x00" + canonical_bytes(core)
            ).digest()
        )
        if snapshot_row["snapshot_hash"] != expected_hash or not core.get(
            "application_eligible"
        ):
            raise SpeciesError("incoming_not_application_eligible")
        if core.get("path_page", {}).get("continuation_release") is not None:
            raise SpeciesError("incoming_path_incomplete")
        target = release_ref(core["selected_candidate"])
        subject = _text(core["subject_me_id"], "species_subject", maximum=240)
        lineage = _typed_id(core["species_id"], _SPECIES_ID, "species_id")
        enrollment = _typed_id(
            core["enrollment_release_id"], _RELEASE_ID, "enrollment_release_id"
        )
        policy_ref = validate_content_ref(local_policy_ref)
        policy = self._local_policy(_content_json(self.cas, policy_ref))
        if not policy["auto_apply"] or lineage not in policy["allowed_species"]:
            raise SpeciesError("species_application_veto")
        capability_hash = _hash(capability_grant_set_hash, "capability_grant_set_hash")
        pointer = Path(os.path.abspath(pointer_path))
        with self._database() as database:
            material = database.execute(
                "SELECT observed_ref_json, evidence_refs_json FROM snapshot_material "
                "WHERE snapshot_hash=?",
                (expected_hash,),
            ).fetchone()
            set_row = database.execute(
                "SELECT page_set_hash FROM snapshot_sets WHERE snapshot_hash=?",
                (expected_hash,),
            ).fetchone()
            if material is None or set_row is None:
                raise SpeciesError("incoming_snapshot_not_stored")
            observed_ref = json.loads(bytes(material["observed_ref_json"]))
            evidence_refs = json.loads(bytes(material["evidence_refs_json"]))
            terminal_page = _uint(
                core["path_page"]["page_index"], "incoming_page_index"
            )
            set_pages = database.execute(
                "SELECT page_index, snapshot_hash, snapshot_ref_json "
                "FROM snapshot_sets WHERE page_set_hash=? ORDER BY page_index",
                (set_row["page_set_hash"],),
            ).fetchall()
            if [int(item["page_index"]) for item in set_pages] != list(
                range(terminal_page + 1)
            ):
                raise SpeciesError("incoming_page_set_incomplete")
            snapshot_refs: list[dict[str, Any]] = []
            stored_pages: list[Mapping[str, Any]] = []
            for item in set_pages:
                reference = validate_content_ref(
                    json.loads(bytes(item["snapshot_ref_json"])),
                    media_type=(
                        "application/vnd.daimon.daimon-species-incoming-result.v0+json"
                    ),
                )
                page_value = _closed(
                    _content_json(self.cas, reference),
                    {"schema", "snapshot_core", "snapshot_hash"},
                    "incoming_fields",
                )
                page_core = page_value["snapshot_core"]
                if (
                    page_value["schema"] != INCOMING_SCHEMA
                    or not isinstance(page_core, Mapping)
                    or page_value["snapshot_hash"] != item["snapshot_hash"]
                    or page_value["snapshot_hash"]
                    != b64url(
                        hashlib.sha256(
                            b"daimon/species-incoming-snapshot/v0\x00"
                            + canonical_bytes(page_core)
                        ).digest()
                    )
                ):
                    raise SpeciesError("incoming_page_hash_mismatch")
                snapshot_refs.append(reference)
                stored_pages.append(page_value)
            if canonical_bytes(stored_pages[-1]) != canonical_bytes(snapshot_row):
                raise SpeciesError("incoming_terminal_page_mismatch")
            terminal_without_path = {
                key: value
                for key, value in core.items()
                if key not in {"application_eligible", "path_page", "reason_codes"}
            }
            terminal_reasons = set(core["reason_codes"])
            previous_end: Mapping[str, Any] | None = None
            previous_continuation: Mapping[str, Any] | None = None
            for index, page_value in enumerate(stored_pages):
                page_core = page_value["snapshot_core"]
                page_path = page_core["path_page"]
                if (
                    page_path["page_index"] != index
                    or {
                        key: value
                        for key, value in page_core.items()
                        if key
                        not in {"application_eligible", "path_page", "reason_codes"}
                    }
                    != terminal_without_path
                ):
                    raise SpeciesError("incoming_page_binding_mismatch")
                reasons = set(page_core["reason_codes"])
                is_terminal = index == terminal_page
                expected_reasons = (
                    terminal_reasons
                    if is_terminal
                    else terminal_reasons | {"path-continues"}
                )
                if (
                    reasons != expected_reasons
                    or bool(page_core["application_eligible"]) != is_terminal
                    or (is_terminal and page_path["continuation_release"] is not None)
                    or (not is_terminal and page_path["continuation_release"] is None)
                ):
                    raise SpeciesError("incoming_page_state_mismatch")
                if index > 0:
                    releases = page_path["releases"]
                    if (
                        page_path["start_release"] != previous_end
                        or not releases
                        or releases[0] != previous_continuation
                    ):
                        raise SpeciesError("incoming_page_continuation_mismatch")
                previous_end = page_path["end_release"]
                previous_continuation = page_path["continuation_release"]
            if previous_end != target:
                raise SpeciesError("incoming_page_target_mismatch")
            release_row = self._release_row(database, target["artifact_id"])
            if release_row is None or release_row["state"] != "accepted":
                raise SpeciesError("species_application_target_changed")
            release_body = validate_release_body(
                self._artifact_from_row(release_row)["body"]
            )
            if canonical_bytes(policy["resource_profile_ref"]) != canonical_bytes(
                release_body["genome"]["compatibility_requirements"]["resource_profile"]
            ):
                raise SpeciesError("species_application_resource_profile")
            head = self._application_head(database, subject, lineage)
            effective = self._effective_release(head)
            mode = "bootstrap" if head is None else "forward"
            if mode == "bootstrap" and target["artifact_id"] != enrollment:
                raise SpeciesError("species_bootstrap_not_enrollment")
            if mode == "forward" and effective != core["effective_applied_release"]:
                raise SpeciesError("species_application_head_changed")
            application_sequence = (
                0 if head is None else int(head["application_sequence"]) + 1
            )
            previous_application = None if head is None else self._application_ref(head)
            prior_manifest_ref = None
            prior_pointer: bytes | None = None
            if pointer.exists():
                prior_pointer = pointer.read_bytes()
                try:
                    prior_manifest = json.loads(prior_pointer)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise SpeciesError("species_pointer_corrupt") from error
                checked_prior = self._runtime_manifest(prior_manifest)
                prior_manifest_ref = self.cas.put(
                    canonical_bytes(checked_prior),
                    "application/vnd.daimon.species-runtime-manifest.v0+json",
                )
            if head is None:
                if prior_manifest_ref is not None:
                    raise SpeciesError("species_unmanifested_runtime")
            else:
                head_payload = self.validate_application_payload(
                    self._application_payload(head)
                )
                if head_payload[
                    "resulting_runtime_manifest_ref"
                ] is None or canonical_bytes(
                    head_payload["resulting_runtime_manifest_ref"]
                ) != canonical_bytes(prior_manifest_ref):
                    raise SpeciesError("species_effective_runtime_mismatch")
                assert prior_manifest_ref is not None
                prior_runtime = self._runtime_manifest(
                    _content_json(self.cas, prior_manifest_ref)
                )
                if prior_runtime["capability_grant_set_hash"] != capability_hash:
                    raise SpeciesError("species_capability_grant_set_changed")
            runtime_manifest = {
                "capability_grant_set_hash": capability_hash,
                "code_config_pointer_digest": release_body["implementation_bundle"][
                    "sha256"
                ],
                "implementation_bundle_ref": release_body["implementation_bundle"],
                "release": target,
                "schema": "species-runtime-manifest/v0",
            }
            checked_runtime = self._runtime_manifest(runtime_manifest)
            runtime_ref = self.cas.put(
                canonical_bytes(checked_runtime),
                "application/vnd.daimon.species-runtime-manifest.v0+json",
            )
            verification = {
                "enrollment_release_id": enrollment,
                "forward": {
                    "evidence_refs": evidence_refs,
                    "observed_positions_manifest_ref": observed_ref,
                    "snapshot_page_refs": snapshot_refs,
                },
                "from_release": effective,
                "implementation_bundle_ref": release_body["implementation_bundle"],
                "mode": mode,
                "rollback": None,
                "schema": "species-application-verification/v0",
                "species_id": lineage,
                "subject_me_id": subject,
                "to_release": target,
            }
            checked_verification = self._verification_manifest(verification)
            verification_ref = self.cas.put(
                canonical_bytes(checked_verification),
                "application/vnd.daimon.species-application-verification.v0+json",
            )
            payload = self.validate_application_payload(
                {
                    "application_sequence": application_sequence,
                    "applied_at_ms": _uint(applied_at_ms, "species_applied_at"),
                    "enrollment_release_id": enrollment,
                    "from_release": effective,
                    "implementation_bundle_ref": release_body["implementation_bundle"],
                    "local_policy_ref": policy_ref,
                    "previous_application": previous_application,
                    "prior_runtime_manifest_ref": prior_manifest_ref,
                    "result": "applied",
                    "resulting_runtime_manifest_ref": runtime_ref,
                    "schema": APPLICATION_SCHEMA,
                    "species_id": lineage,
                    "subject_me_id": subject,
                    "to_release": target,
                    "verification_manifest_ref": verification_ref,
                }
            )
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT state, event_id, payload_json FROM application_journal "
                    "WHERE operation_id=?",
                    (operation,),
                ).fetchone()
                if existing is not None:
                    if bytes(existing["payload_json"]) != canonical_bytes(payload):
                        raise SpeciesError("species_operation_conflict")
                    if existing["state"] == "committed" and existing["event_id"]:
                        replay_payload = self.validate_application_payload(
                            json.loads(bytes(existing["payload_json"]))
                        )
                        database.rollback()
                        return {
                            "event_id": str(existing["event_id"]),
                            "operation_id": operation,
                            "result": replay_payload["result"],
                            "replayed": True,
                        }
                    raise SpeciesError("species_operation_recovery_required")
                database.execute(
                    "INSERT INTO application_journal VALUES "
                    "(?, ?, ?, 'prepared', ?, ?, ?, ?)",
                    (
                        operation,
                        subject,
                        lineage,
                        prior_pointer,
                        canonical_bytes(checked_runtime),
                        canonical_bytes(payload),
                        expected_event_id,
                    ),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        if fault_hook is not None:
            fault_hook("after_application_prepared")
        self._atomic_pointer(pointer, canonical_bytes(checked_runtime))
        with self._database() as database:
            database.execute(
                "UPDATE application_journal SET state='switched' WHERE operation_id=?",
                (operation,),
            )
        if fault_hook is not None:
            fault_hook("after_application_pointer_switch")
        event = append_event(payload)
        recorded = self.record_application_event(event)
        if recorded["event_id"] != expected_event_id:
            raise SpeciesError("species_application_event_id_mismatch")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "UPDATE application_journal SET state='event-appended', event_id=? "
                    "WHERE operation_id=?",
                    (recorded["event_id"], operation),
                )
                if fault_hook is not None:
                    fault_hook("after_application_event")
                database.execute(
                    "UPDATE application_journal SET state='committed' "
                    "WHERE operation_id=?",
                    (operation,),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "event_id": recorded["event_id"],
            "operation_id": operation,
            "result": "applied",
            "replayed": False,
        }

    def rollback(
        self,
        *,
        operation_id: str,
        snapshot: Mapping[str, Any],
        local_policy_ref: Mapping[str, Any],
        capability_grant_set_hash: str,
        pointer_path: str | Path,
        applied_at_ms: int,
        reason: str,
        append_event: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        with self._exclusive_application_lock():
            return self._rollback_locked(
                operation_id=operation_id,
                snapshot=snapshot,
                local_policy_ref=local_policy_ref,
                capability_grant_set_hash=capability_grant_set_hash,
                pointer_path=pointer_path,
                applied_at_ms=applied_at_ms,
                reason=reason,
                append_event=append_event,
                fault_hook=fault_hook,
            )

    def _rollback_locked(
        self,
        *,
        operation_id: str,
        snapshot: Mapping[str, Any],
        local_policy_ref: Mapping[str, Any],
        capability_grant_set_hash: str,
        pointer_path: str | Path,
        applied_at_ms: int,
        reason: str,
        append_event: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        fault_hook: Callable[[str], None] | None,
    ) -> dict[str, Any]:
        """Restore one previously applied runtime through a successor event."""

        self.initialize()
        try:
            operation = str(uuid.UUID(operation_id))
        except ValueError as error:
            raise SpeciesError("species_operation_id") from error
        expected_event_id = str(
            uuid.uuid5(uuid.UUID(operation), APPLICATION_EVENT_KIND)
        )
        snapshot_row = _closed(
            snapshot, {"schema", "snapshot_core", "snapshot_hash"}, "incoming_fields"
        )
        core = snapshot_row["snapshot_core"]
        if snapshot_row["schema"] != INCOMING_SCHEMA or not isinstance(core, Mapping):
            raise SpeciesError("incoming_schema")
        expected_hash = b64url(
            hashlib.sha256(
                b"daimon/species-incoming-snapshot/v0\x00" + canonical_bytes(core)
            ).digest()
        )
        if snapshot_row["snapshot_hash"] != expected_hash:
            raise SpeciesError("incoming_snapshot_hash")
        if reason not in {"release-fork", "runtime-failure"}:
            raise SpeciesError("species_rollback_reason")
        if reason == "release-fork":
            if core.get("state") != "quarantined" or not core.get("conflict_refs"):
                raise SpeciesError("species_release_fork_proof_missing")
        elif core.get("state") == "quarantined" or core.get("conflict_refs"):
            raise SpeciesError("species_runtime_failure_snapshot_invalid")
        subject = _text(core["subject_me_id"], "species_subject", maximum=240)
        lineage = _typed_id(core["species_id"], _SPECIES_ID, "species_id")
        enrollment = _typed_id(
            core["enrollment_release_id"], _RELEASE_ID, "enrollment_release_id"
        )
        policy_ref = validate_content_ref(local_policy_ref)
        self.load_local_policy(policy_ref)
        capability_hash = _hash(capability_grant_set_hash, "capability_grant_set_hash")
        pointer = Path(os.path.abspath(pointer_path))
        with self._database() as database:
            material = database.execute(
                "SELECT observed_ref_json FROM snapshot_material WHERE snapshot_hash=?",
                (expected_hash,),
            ).fetchone()
            snapshot_page = database.execute(
                "SELECT snapshot_ref_json FROM snapshot_sets WHERE snapshot_hash=?",
                (expected_hash,),
            ).fetchone()
            state_row = database.execute(
                "SELECT accepted_id FROM species_state WHERE species_id=?",
                (lineage,),
            ).fetchone()
            current_head = self._application_head(database, subject, lineage)
            if (
                material is None
                or snapshot_page is None
                or state_row is None
                or current_head is None
                or state_row["accepted_id"] is None
            ):
                raise SpeciesError(
                    "species_rollback_evidence_incomplete", incomplete=True
                )
            current_payload = self.validate_application_payload(
                self._application_payload(current_head)
            )
            current_release = self._effective_release(current_head)
            if current_release is None:
                raise SpeciesError("species_rollback_current_runtime_missing")
            accepted_head_id = str(state_row["accepted_id"])
            runtime_failure_target_id = (
                None
                if current_payload["from_release"] is None
                else current_payload["from_release"]["artifact_id"]
            )
            if reason == "runtime-failure" and runtime_failure_target_id is None:
                raise SpeciesError("species_rollback_below_enrollment")
            target_application: sqlite3.Row | None = None
            for candidate in database.execute(
                "SELECT * FROM applications WHERE subject_me_id=? AND species_id=? "
                "AND state='accepted' AND application_sequence<? "
                "ORDER BY application_sequence DESC",
                (subject, lineage, current_payload["application_sequence"]),
            ):
                candidate_payload = self.validate_application_payload(
                    self._application_payload(candidate)
                )
                candidate_id = candidate_payload["to_release"]["artifact_id"]
                eligible_target = candidate_id == runtime_failure_target_id
                if reason == "release-fork":
                    try:
                        self._path(database, candidate_id, accepted_head_id)
                    except SpeciesError:
                        eligible_target = False
                    else:
                        eligible_target = True
                if candidate_payload["result"] == "applied" and eligible_target:
                    target_application = candidate
                    break
            if target_application is None:
                raise SpeciesError("species_rollback_target_not_applied")
            target_payload = self.validate_application_payload(
                self._application_payload(target_application)
            )
            if target_payload["to_release"]["artifact_id"] == enrollment:
                target_release = target_payload["to_release"]
            else:
                target_release = target_payload["to_release"]
            prior_runtime_ref = current_payload["resulting_runtime_manifest_ref"]
            target_runtime_ref = target_payload["resulting_runtime_manifest_ref"]
            if prior_runtime_ref is None or target_runtime_ref is None:
                raise SpeciesError("species_rollback_runtime_missing", incomplete=True)
            prior_runtime = self._runtime_manifest(
                _content_json(self.cas, prior_runtime_ref)
            )
            target_runtime = self._runtime_manifest(
                _content_json(self.cas, target_runtime_ref)
            )
            if (
                prior_runtime["release"] != current_release
                or target_runtime["release"] != target_release
                or prior_runtime["capability_grant_set_hash"] != capability_hash
                or target_runtime["capability_grant_set_hash"] != capability_hash
            ):
                raise SpeciesError("species_rollback_runtime_mismatch")
            current_pointer = pointer.read_bytes() if pointer.exists() else None
            expected_prior_pointer = canonical_bytes(prior_runtime)
            if current_pointer != expected_prior_pointer:
                raise SpeciesError("species_rollback_pointer_mismatch")
            target_pointer = canonical_bytes(target_runtime)
            observed_ref = json.loads(bytes(material["observed_ref_json"]))
            current_snapshot_ref = json.loads(bytes(snapshot_page["snapshot_ref_json"]))
            verification = self._verification_manifest(
                {
                    "enrollment_release_id": enrollment,
                    "forward": None,
                    "from_release": current_release,
                    "implementation_bundle_ref": target_runtime[
                        "implementation_bundle_ref"
                    ],
                    "mode": "rollback",
                    "rollback": {
                        "current_application": self._application_ref(current_head),
                        "current_snapshot_ref": current_snapshot_ref,
                        "observed_positions_manifest_ref": observed_ref,
                        "reason": reason,
                        "target_application": self._application_ref(target_application),
                        "target_runtime_manifest_ref": target_runtime_ref,
                    },
                    "schema": "species-application-verification/v0",
                    "species_id": lineage,
                    "subject_me_id": subject,
                    "to_release": target_release,
                }
            )
            verification_ref = self.cas.put(
                canonical_bytes(verification),
                "application/vnd.daimon.species-application-verification.v0+json",
            )
            payload = self.validate_application_payload(
                {
                    "application_sequence": current_payload["application_sequence"] + 1,
                    "applied_at_ms": _uint(applied_at_ms, "species_applied_at"),
                    "enrollment_release_id": enrollment,
                    "from_release": current_release,
                    "implementation_bundle_ref": target_runtime[
                        "implementation_bundle_ref"
                    ],
                    "local_policy_ref": policy_ref,
                    "previous_application": self._application_ref(current_head),
                    "prior_runtime_manifest_ref": prior_runtime_ref,
                    "result": "rolled-back",
                    "resulting_runtime_manifest_ref": target_runtime_ref,
                    "schema": APPLICATION_SCHEMA,
                    "species_id": lineage,
                    "subject_me_id": subject,
                    "to_release": target_release,
                    "verification_manifest_ref": verification_ref,
                }
            )
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT state, event_id, payload_json FROM application_journal "
                    "WHERE operation_id=?",
                    (operation,),
                ).fetchone()
                if existing is not None:
                    if bytes(existing["payload_json"]) != canonical_bytes(payload):
                        raise SpeciesError("species_operation_conflict")
                    if existing["state"] == "committed":
                        database.rollback()
                        return {
                            "event_id": str(existing["event_id"]),
                            "operation_id": operation,
                            "result": "rolled-back",
                            "replayed": True,
                        }
                    raise SpeciesError("species_operation_recovery_required")
                database.execute(
                    "INSERT INTO application_journal VALUES "
                    "(?, ?, ?, 'prepared', ?, ?, ?, ?)",
                    (
                        operation,
                        subject,
                        lineage,
                        current_pointer,
                        target_pointer,
                        canonical_bytes(payload),
                        expected_event_id,
                    ),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        if fault_hook is not None:
            fault_hook("after_application_prepared")
        self._atomic_pointer(pointer, target_pointer)
        with self._database() as database:
            database.execute(
                "UPDATE application_journal SET state='switched' WHERE operation_id=?",
                (operation,),
            )
        if fault_hook is not None:
            fault_hook("after_application_pointer_switch")
        event = append_event(payload)
        recorded = self.record_application_event(event)
        if recorded["event_id"] != expected_event_id:
            raise SpeciesError("species_application_event_id_mismatch")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "UPDATE application_journal SET state='event-appended' "
                    "WHERE operation_id=?",
                    (operation,),
                )
                if fault_hook is not None:
                    fault_hook("after_application_event")
                database.execute(
                    "UPDATE application_journal SET state='committed' "
                    "WHERE operation_id=?",
                    (operation,),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return {
            "event_id": recorded["event_id"],
            "operation_id": operation,
            "result": "rolled-back",
            "replayed": False,
        }

    def recover_application(
        self,
        operation_id: str,
        pointer_path: str | Path,
        *,
        find_event: Callable[[str], Mapping[str, Any] | None] | None = None,
    ) -> str:
        """Rollback an unrecorded switch or complete its exact durable event."""

        with self._exclusive_application_lock():
            return self._recover_application_locked(
                operation_id, pointer_path, find_event=find_event
            )

    def _recover_application_locked(
        self,
        operation_id: str,
        pointer_path: str | Path,
        *,
        find_event: Callable[[str], Mapping[str, Any] | None] | None,
    ) -> str:
        self.initialize()
        try:
            operation = str(uuid.UUID(operation_id))
        except ValueError as error:
            raise SpeciesError("species_operation_id") from error
        pointer = Path(os.path.abspath(pointer_path))
        with self._database() as database:
            row = database.execute(
                "SELECT * FROM application_journal WHERE operation_id=?",
                (operation,),
            ).fetchone()
            if row is None:
                raise SpeciesError("species_operation_missing")
            journal: dict[str, Any] = {
                "event_id": str(row["event_id"]),
                "payload": bytes(row["payload_json"]),
                "prior_pointer": None
                if row["prior_pointer"] is None
                else bytes(row["prior_pointer"]),
                "state": str(row["state"]),
                "target_pointer": bytes(row["target_pointer"]),
            }
        if journal["state"] == "committed":
            return "committed"
        if journal["state"] == "rolled-back":
            return "rolled-back"

        durable_event = (
            None if find_event is None else find_event(str(journal["event_id"]))
        )
        event_is_durable = journal["state"] == "event-appended"
        if durable_event is not None:
            if (
                not isinstance(durable_event, Mapping)
                or canonical_bytes(durable_event.get("payload")) != journal["payload"]
            ):
                raise SpeciesError("species_recovery_event_mismatch")
            recorded = self.record_application_event(durable_event)
            if recorded["event_id"] != journal["event_id"]:
                raise SpeciesError("species_recovery_event_mismatch")
            event_is_durable = True
        if event_is_durable:
            current = pointer.read_bytes() if pointer.exists() else None
            if current != journal["target_pointer"]:
                self._atomic_pointer(pointer, journal["target_pointer"])
            with self._database() as database:
                database.execute(
                    "UPDATE application_journal SET state='committed' "
                    "WHERE operation_id=?",
                    (operation,),
                )
            return "committed"

        prior = journal["prior_pointer"]
        if prior is None:
            if pointer.exists():
                pointer.unlink()
                directory = os.open(
                    pointer.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        else:
            self._atomic_pointer(pointer, prior)
        with self._database() as database:
            database.execute(
                "UPDATE application_journal SET state='rolled-back' "
                "WHERE operation_id=?",
                (operation,),
            )
        return "rolled-back"

    def recover_pending_applications(
        self,
        pointer_path: str | Path,
        *,
        find_event: Callable[[str], Mapping[str, Any] | None],
    ) -> list[dict[str, str]]:
        """Recover every fenced operation before a hosted runtime can serve."""

        self.initialize()
        with self._database() as database:
            operations = [
                str(row["operation_id"])
                for row in database.execute(
                    "SELECT operation_id FROM application_journal "
                    "WHERE state NOT IN ('committed','rolled-back') "
                    "ORDER BY operation_id"
                )
            ]
        return [
            {
                "operation_id": operation,
                "state": self.recover_application(
                    operation, pointer_path, find_event=find_event
                ),
            }
            for operation in operations
        ]
