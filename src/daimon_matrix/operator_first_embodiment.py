"""Split-custody activation of the first runtime for a distributed genesis."""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import b64url, canonical_bytes, digest, domain_bytes
from .client import CLIENT_CONFIG_SCHEMA_V3
from .identity import (
    DOMAINS,
    ControlState,
    signing_descriptor,
    verify_embodiment_credential,
    verify_genesis,
    verify_incarnation_authorization,
)
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .operator_capabilities import (
    HOST_PROFILE_NAMES,
    OBSERVE_PROFILE,
    OPERATOR_PROFILE_NAMES,
    OperatorCapabilityError,
    create_operator_capability_binding,
    host_capability_profile,
    operator_capability_profile,
)
from .operator_genesis import HOLDER_SCHEMA, PENDING_CONTROL_HEAD
from .operator_rebirth import (
    RebirthError,
    _holder_attestation,
    _identity_signature,
    _origin,
    _validated_preparation,
    _verify_holder_attestation,
    create_target_preparation,
    validate_enrollment_request,
)
from .weave import BeingManifest, RootAuthority

SHARE_SCHEMA: Final = "dm.operator.first-embodiment-root-share/v1"
SHARE_DOMAIN: Final = "dm.operator.first-embodiment-root-share/v1"
ACTIVATION_SCHEMA: Final = "dm.operator.first-embodiment-activation/v1"
ACTIVATION_DOMAIN: Final = "dm.operator.first-embodiment-activation/v1"
ACTIVATION_ID_PREFIX: Final = "dm:first-embodiment-activation:v1:"
INITIAL_BASE_SCHEMA: Final = "dm.operator.initial-manifest-base/v1"
RECEIPT_SCHEMA: Final = "dm.operator.first-embodiment-runtime-receipt/v1"
REQUEST_LIFETIME_MS: Final = 7 * 24 * 60 * 60 * 1000
MAX_DOCUMENT_BYTES: Final = 4 * 1024 * 1024


class FirstEmbodimentError(RuntimeError):
    """The first embodiment ceremony failed closed."""


@dataclass(frozen=True)
class _InitialBase:
    manifest: BeingManifest
    state: ControlState


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise FirstEmbodimentError(code)
    return value


def _initial_base(genesis: Any) -> _InitialBase:
    if not isinstance(genesis, Mapping):
        raise FirstEmbodimentError("invalid_first_embodiment_genesis")
    try:
        state = verify_genesis(genesis)
    except (TypeError, ValueError) as exception:
        raise FirstEmbodimentError("invalid_first_embodiment_genesis") from exception
    value = {
        "schema": INITIAL_BASE_SCHEMA,
        "being_ref": state.being_ref,
        "control_head": state.head,
        "revision": 0,
        "embodiments": [],
    }
    return _InitialBase(
        manifest=BeingManifest(
            value=value,
            digest=hashlib.sha256(canonical_bytes(value)).hexdigest(),
            trust_mode="root-bound",
        ),
        state=state,
    )


def _owner_directory(path: Path, code: str) -> Path:
    target = Path(os.path.abspath(path))
    _reject_symlink_ancestors(target, code)
    try:
        info = target.lstat()
    except OSError as exception:
        raise FirstEmbodimentError(code) from exception
    if (
        target.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise FirstEmbodimentError(code)
    return target


def _reject_symlink_ancestors(path: Path, code: str) -> None:
    ancestor = path.parent
    while ancestor != ancestor.parent:
        try:
            info = ancestor.lstat()
        except OSError as exception:
            raise FirstEmbodimentError(code) from exception
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise FirstEmbodimentError(code)
        ancestor = ancestor.parent


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_write(path: Path, value: Mapping[str, Any] | bytes) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _document(path: Path, code: str) -> Any:
    target = Path(os.path.abspath(path))
    _reject_symlink_ancestors(target, code)
    descriptor = -1
    try:
        before = target.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 1 <= before.st_size <= MAX_DOCUMENT_BYTES
        ):
            raise FirstEmbodimentError(code)
        descriptor = os.open(
            target,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) & 0o077
            or not 1 <= after.st_size <= MAX_DOCUMENT_BYTES
        ):
            raise FirstEmbodimentError(code)
        raw = b""
        while chunk := os.read(descriptor, 1024 * 1024):
            raw += chunk
            if len(raw) > MAX_DOCUMENT_BYTES:
                raise FirstEmbodimentError(code)
        value = json.loads(raw)
        if canonical_bytes(value) != raw.rstrip(b"\n"):
            raise FirstEmbodimentError(code)
        return value
    except FirstEmbodimentError:
        raise
    except (OSError, ValueError) as exception:
        raise FirstEmbodimentError(code) from exception
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    _owner_directory(target.parent, "first_embodiment_output_parent_rejected")
    if target.exists() or target.is_symlink():
        if target.is_file() and canonical_bytes(
            _document(target, "first_embodiment_output_exists")
        ) == canonical_bytes(value):
            return
        raise FirstEmbodimentError("first_embodiment_output_exists")
    _private_write(target, value)
    _fsync_directory(target.parent)


def _password(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise FirstEmbodimentError("invalid_first_embodiment_password_descriptor")
    try:
        raw = os.read(descriptor, 1025)
    except OSError as exception:
        raise FirstEmbodimentError(
            "first_embodiment_password_unavailable"
        ) from exception
    finally:
        with contextlib.suppress(OSError):
            os.close(descriptor)
    if not 12 <= len(raw) <= 1024:
        raise FirstEmbodimentError("invalid_first_embodiment_password_length")
    return bytearray(raw)


def _reader(password: bytearray) -> PasswordReader:
    return lambda: bytearray(password)


def prepare_target(
    output: Path,
    genesis: Any,
    profile: Any,
    password_reader: PasswordReader,
    *,
    created_at_ms: int,
) -> dict[str, Any]:
    """Create target-only custody and a body-accepted public request."""

    base = _initial_base(genesis)
    try:
        return create_target_preparation(
            output,
            base,
            profile,
            password_reader,
            created_at_ms=created_at_ms,
            expires_at_ms=created_at_ms + REQUEST_LIFETIME_MS,
            expected_targets=set(),
        )
    except RebirthError as exception:
        raise FirstEmbodimentError(
            "first_embodiment_preparation_rejected"
        ) from exception


def _root_holder_seed(
    holder: Path,
    base: _InitialBase,
    password_reader: PasswordReader,
) -> bytes:
    package = _owner_directory(holder, "first_embodiment_root_holder_rejected")
    descriptor = _closed(
        _document(package / "descriptor.json", "first_embodiment_root_holder_rejected"),
        {"schema", "role", "key"},
        "first_embodiment_root_holder_rejected",
    )
    if (
        descriptor["schema"] != HOLDER_SCHEMA
        or descriptor["role"] != "root"
        or not isinstance(descriptor["key"], Mapping)
    ):
        raise FirstEmbodimentError("first_embodiment_root_holder_rejected")
    try:
        contents = EncryptedKeystore(package / "holder.json").open(
            password_reader,
            minimum_counter=1,
            required_control_head=PENDING_CONTROL_HEAD,
        )
    except KeystoreError as exception:
        raise FirstEmbodimentError(
            "first_embodiment_root_holder_rejected"
        ) from exception
    if set(contents.secrets) != {"genesis.root.v1:holder"}:
        raise FirstEmbodimentError("first_embodiment_root_holder_rejected")
    seed = contents.secrets["genesis.root.v1:holder"]
    key = signing_descriptor(seed)
    if key != descriptor["key"] or key["key_id"] not in {
        row["key_id"] for row in base.state.root_policy["keys"]
    }:
        raise FirstEmbodimentError("first_embodiment_root_holder_rejected")
    return seed


def create_root_share(
    genesis: Any,
    request: Any,
    holder: Path,
    password_reader: PasswordReader,
    *,
    observed_at_ms: int,
) -> dict[str, Any]:
    """Open one isolated root package and attest the exact target request."""

    base = _initial_base(genesis)
    try:
        verified = validate_enrollment_request(
            request,
            base,
            observed_at_ms=observed_at_ms,
        )
    except (KeyError, RebirthError, TypeError) as exception:
        raise FirstEmbodimentError("first_embodiment_request_rejected") from exception
    seed = _root_holder_seed(holder, base, password_reader)
    credential = verified["body"]["credential"]
    signature = _identity_signature(
        seed,
        "root-authorization",
        domain_bytes(DOMAINS["embodiment-credential"], credential["body"]),
    )
    share_body = {
        "being_ref": base.state.being_ref,
        "control_head": base.state.head,
        "request_id": verified["request_id"],
        "request_sha256": hashlib.sha256(canonical_bytes(verified)).hexdigest(),
        "credential_signature": signature,
    }
    return {
        "schema": SHARE_SCHEMA,
        **share_body,
        "attestation": _holder_attestation(seed, SHARE_DOMAIN, share_body),
    }


def _expected_manifest(
    base: _InitialBase,
    credential: Mapping[str, Any],
    incarnation: Mapping[str, Any],
    origin: Mapping[str, Any],
) -> BeingManifest:
    return BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": base.state.being_ref,
            "control_head": base.state.head,
            "history_binding_id": None,
            "revision": 1,
            "embodiments": [
                {
                    "body_ref": origin["body_ref"],
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": origin["embodiment_id"],
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": origin["incarnation_id"],
                    "status": "active",
                }
            ],
        }
    )


def aggregate_activation(
    genesis: Any,
    request: Any,
    shares: Sequence[Any],
    *,
    observed_at_ms: int,
) -> dict[str, Any]:
    """Keyless aggregation of root shares into one first-runtime activation."""

    base = _initial_base(genesis)
    try:
        issued_at_ms = observed_at_ms
        verified = validate_enrollment_request(
            request, base, observed_at_ms=issued_at_ms
        )
    except (KeyError, RebirthError, TypeError) as exception:
        raise FirstEmbodimentError("first_embodiment_request_rejected") from exception
    credential = copy.deepcopy(verified["body"]["credential"])
    request_sha256 = hashlib.sha256(canonical_bytes(verified)).hexdigest()
    signatures: list[Mapping[str, Any]] = []
    approvals: list[dict[str, Any]] = []
    approved_ids: set[str] = set()
    for value in shares:
        row = _closed(
            value,
            {
                "schema",
                "being_ref",
                "control_head",
                "request_id",
                "request_sha256",
                "credential_signature",
                "attestation",
            },
            "first_embodiment_share_rejected",
        )
        credential_signature = row["credential_signature"]
        if (
            row["schema"] != SHARE_SCHEMA
            or row["being_ref"] != base.state.being_ref
            or row["control_head"] != base.state.head
            or row["request_id"] != verified["request_id"]
            or row["request_sha256"] != request_sha256
            or not isinstance(credential_signature, Mapping)
            or credential_signature.get("role") != "root-authorization"
        ):
            raise FirstEmbodimentError("first_embodiment_share_rejected")
        share_body = {
            "being_ref": row["being_ref"],
            "control_head": row["control_head"],
            "request_id": row["request_id"],
            "request_sha256": row["request_sha256"],
            "credential_signature": credential_signature,
        }
        try:
            attested_kid = _verify_holder_attestation(
                row["attestation"],
                SHARE_DOMAIN,
                share_body,
                base.state.root_policy["keys"],
                code="first_embodiment_share_rejected",
            )
        except RebirthError as exception:
            raise FirstEmbodimentError("first_embodiment_share_rejected") from exception
        if (
            credential_signature.get("key_id") != attested_kid
            or attested_kid in approved_ids
        ):
            raise FirstEmbodimentError("first_embodiment_share_rejected")
        approved_ids.add(attested_kid)
        signatures.append(copy.deepcopy(dict(credential_signature)))
        approvals.append(
            {
                **copy.deepcopy(share_body),
                "attestation": copy.deepcopy(dict(row["attestation"])),
            }
        )
    credential["signatures"].extend(signatures)
    credential["signatures"].sort(key=lambda row: (row["key_id"], row["role"]))
    approvals.sort(key=lambda row: row["attestation"]["kid"])
    incarnation = copy.deepcopy(verified["body"]["incarnation"])
    try:
        credential_body = verify_embodiment_credential(
            credential, base.state, at_ms=issued_at_ms
        )
        incarnation_body = verify_incarnation_authorization(
            incarnation, credential, base.state, at_ms=issued_at_ms
        )
    except ValueError as exception:
        raise FirstEmbodimentError("first_embodiment_threshold_rejected") from exception
    origin = _origin(verified["body"]["origin"])
    if (
        credential_body["embodiment_id"] != origin["embodiment_id"]
        or credential_body["body_ref"] != origin["body_ref"]
        or incarnation_body["incarnation_id"] != origin["incarnation_id"]
        or incarnation_body["incarnation_sequence"] != 0
    ):
        raise FirstEmbodimentError("first_embodiment_binding_rejected")
    manifest = _expected_manifest(base, credential, incarnation, origin)
    RootAuthority(
        manifest,
        base.state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    body = {
        "request_id": verified["request_id"],
        "being_ref": base.state.being_ref,
        "control_head": base.state.head,
        "initial_base_hash": base.manifest.digest,
        "manifest": manifest.value,
        "credential": credential,
        "incarnation": incarnation,
        "origin": origin,
        "root_approvals": approvals,
        "issued_at_ms": issued_at_ms,
    }
    return {
        "schema": ACTIVATION_SCHEMA,
        "activation_id": ACTIVATION_ID_PREFIX + b64url(digest(ACTIVATION_DOMAIN, body)),
        "body": body,
    }


def validate_activation(
    genesis: Any,
    request: Any,
    activation: Any,
) -> tuple[dict[str, Any], RootAuthority]:
    """Validate the complete first manifest and its root-authorized credential."""

    base = _initial_base(genesis)
    row = _closed(
        activation,
        {"schema", "activation_id", "body"},
        "invalid_first_embodiment_activation",
    )
    if row["schema"] != ACTIVATION_SCHEMA:
        raise FirstEmbodimentError("unsupported_first_embodiment_activation")
    body = _closed(
        row["body"],
        {
            "request_id",
            "being_ref",
            "control_head",
            "initial_base_hash",
            "manifest",
            "credential",
            "incarnation",
            "origin",
            "root_approvals",
            "issued_at_ms",
        },
        "invalid_first_embodiment_activation",
    )
    try:
        verified_request = validate_enrollment_request(
            request, base, observed_at_ms=body["issued_at_ms"]
        )
    except RebirthError as exception:
        raise FirstEmbodimentError("first_embodiment_request_rejected") from exception
    if (
        body["request_id"] != verified_request["request_id"]
        or body["being_ref"] != base.state.being_ref
        or body["control_head"] != base.state.head
        or body["initial_base_hash"] != base.manifest.digest
    ):
        raise FirstEmbodimentError("first_embodiment_activation_base_mismatch")
    credential = copy.deepcopy(body["credential"])
    incarnation = copy.deepcopy(body["incarnation"])
    origin = _origin(body["origin"])
    approvals = body["root_approvals"]
    if not isinstance(approvals, list):
        raise FirstEmbodimentError("invalid_first_embodiment_activation")
    request_sha256 = hashlib.sha256(canonical_bytes(verified_request)).hexdigest()
    approved_ids: set[str] = set()
    approved_signatures: list[Mapping[str, Any]] = []
    for value in approvals:
        approval = _closed(
            value,
            {
                "being_ref",
                "control_head",
                "request_id",
                "request_sha256",
                "credential_signature",
                "attestation",
            },
            "invalid_first_embodiment_activation",
        )
        credential_signature = approval["credential_signature"]
        if (
            approval["being_ref"] != base.state.being_ref
            or approval["control_head"] != base.state.head
            or approval["request_id"] != verified_request["request_id"]
            or approval["request_sha256"] != request_sha256
            or not isinstance(credential_signature, Mapping)
            or credential_signature.get("role") != "root-authorization"
        ):
            raise FirstEmbodimentError("invalid_first_embodiment_activation")
        approval_body = {
            key: approval[key]
            for key in (
                "being_ref",
                "control_head",
                "request_id",
                "request_sha256",
                "credential_signature",
            )
        }
        try:
            attested_kid = _verify_holder_attestation(
                approval["attestation"],
                SHARE_DOMAIN,
                approval_body,
                base.state.root_policy["keys"],
                code="invalid_first_embodiment_activation",
            )
        except RebirthError as exception:
            raise FirstEmbodimentError(
                "invalid_first_embodiment_activation"
            ) from exception
        if (
            credential_signature.get("key_id") != attested_kid
            or attested_kid in approved_ids
        ):
            raise FirstEmbodimentError("invalid_first_embodiment_activation")
        approved_ids.add(attested_kid)
        approved_signatures.append(credential_signature)
    root_signatures = [
        signature
        for signature in credential.get("signatures", [])
        if isinstance(signature, Mapping)
        and signature.get("role") == "root-authorization"
    ]
    if canonical_bytes(
        sorted(approved_signatures, key=lambda row: row["key_id"])
    ) != canonical_bytes(sorted(root_signatures, key=lambda row: row["key_id"])):
        raise FirstEmbodimentError("invalid_first_embodiment_activation")
    try:
        verify_embodiment_credential(credential, base.state, at_ms=body["issued_at_ms"])
        verify_incarnation_authorization(
            incarnation, credential, base.state, at_ms=body["issued_at_ms"]
        )
        manifest = BeingManifest.from_value(body["manifest"])
        expected = _expected_manifest(base, credential, incarnation, origin)
        if manifest.digest != expected.digest:
            raise FirstEmbodimentError("first_embodiment_manifest_mismatch")
        authority = RootAuthority(
            manifest,
            base.state,
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
    except ValueError as exception:
        raise FirstEmbodimentError("invalid_first_embodiment_activation") from exception
    expected_id = ACTIVATION_ID_PREFIX + b64url(digest(ACTIVATION_DOMAIN, body))
    if row["activation_id"] != expected_id:
        raise FirstEmbodimentError("first_embodiment_activation_id_mismatch")
    normalized = copy.deepcopy(dict(row))
    if canonical_bytes(normalized) != canonical_bytes(activation):
        raise FirstEmbodimentError("noncanonical_first_embodiment_activation")
    return normalized, authority


def _client(
    runtime_id: str,
    label: str,
    origin: Mapping[str, Any],
    capability: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": CLIENT_CONFIG_SCHEMA_V3,
        "capability": capability,
        "expected_server": copy.deepcopy(dict(origin)),
        "runtime_id": runtime_id,
        "runtime_label": label,
    }


def activate_runtime(
    output: Path,
    genesis: Any,
    preparation_directory: Path,
    preparation: Any,
    request: Any,
    activation: Any,
    password_reader: PasswordReader,
) -> dict[str, Any]:
    """Build one fresh V7 package without centralizing any root seed."""

    base = _initial_base(genesis)
    verified_activation, authority = validate_activation(genesis, request, activation)
    issued_at_ms = verified_activation["body"]["issued_at_ms"]
    try:
        verified_preparation, body_secrets, transport_secrets = _validated_preparation(
            preparation_directory,
            preparation,
            request,
            base,
            password_reader,
            observed_at_ms=issued_at_ms,
            expected_targets=set(),
        )
    except RebirthError as exception:
        raise FirstEmbodimentError("first_embodiment_target_rejected") from exception
    target = Path(os.path.abspath(output))
    parent = _owner_directory(target.parent, "first_embodiment_output_parent_rejected")
    if target.exists() or target.is_symlink():
        raise FirstEmbodimentError("first_embodiment_output_exists")
    staging: Path | None = None
    supplied = password_reader()
    if not isinstance(supplied, (bytes, bytearray)) or not 12 <= len(supplied) <= 1024:
        raise FirstEmbodimentError("invalid_first_embodiment_password_length")
    password = bytearray(supplied)
    if isinstance(supplied, bytearray):
        supplied[:] = b"\x00" * len(supplied)
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=parent))
        staging.chmod(0o700)
        runtime = staging / "runtime"
        runtime.mkdir(mode=0o700)
        operator_clients = runtime / "operator-clients"
        operator_clients.mkdir(mode=0o700)
        host_clients = runtime / "host-clients"
        host_clients.mkdir(mode=0o700)
        profile = verified_preparation["profile"]
        label = profile["label"]
        origin = verified_preparation["origin"]
        runtime_id = verified_preparation["runtime_id"]
        slots = verified_preparation["slots"]
        capabilities = verified_preparation["capabilities"]
        host_capabilities = verified_preparation["host_capabilities"]
        capability_rows = [
            {
                "descriptor": capabilities[name],
                "profile": operator_capability_profile(name),
                "runtime_id": runtime_id,
                "secret_slot": slots["operator_capabilities"][name],
            }
            for name in OPERATOR_PROFILE_NAMES
        ]
        capability_rows.extend(
            {
                "descriptor": host_capabilities[name],
                "profile": host_capability_profile(name),
                "runtime_id": runtime_id,
                "secret_slot": slots["host_capabilities"][name],
            }
            for name in HOST_PROFILE_NAMES
        )
        try:
            capability_binding = create_operator_capability_binding(
                runtime_id=runtime_id,
                runtime_label=label,
                being_ref=authority.manifest.being_ref,
                origin=origin,
                signing_seed=body_secrets[slots["signing"]],
                capability_rows=capability_rows,
            )
        except (KeyError, OperatorCapabilityError) as exception:
            raise FirstEmbodimentError(
                "first_embodiment_target_capability_rejected"
            ) from exception
        bundle = {
            "schema": "dm.runtime.bundle/v7",
            "runtime_id": runtime_id,
            "runtime_label": label,
            "control_artifacts": [copy.deepcopy(dict(genesis))],
            "control_head": authority.state.head,
            "manifest": authority.manifest.value,
            "authority_history": [],
            "credentials": list(authority.credentials.values()),
            "incarnations": list(authority.incarnations.values()),
            "binding": None,
            "binding_activation": None,
            "provisional_history": None,
            "local_origin": origin,
            "ledger": "ledger.sqlite",
            "socket": "matrix.sock",
            "keystore": {
                "filename": "custody.json",
                "counter": 1,
                "signing_slot": slots["signing"],
            },
            "capabilities": capability_rows,
            "operator_capability_binding": capability_binding,
            "routing": None,
            "scopes": {"body_capabilities": [], "relationships_filename": None},
            "peer_transport": {
                "enabled": True,
                "encryption_slot": slots["encryption"],
                "exchange_filename": "peer-exchange.sqlite",
                "listen_host": profile["listen_host"],
                "listen_port": profile["listen_port"],
                "outbox_filename": "peer-outbox.sqlite",
                "targets": [],
            },
            "species": None,
            "sources": {"cas_filename": "sources.sqlite3", "known_beings": []},
            "relationships": {
                "known_being_refs": [],
                "store_filename": "relationships.sqlite3",
            },
        }
        EncryptedKeystore.create(
            runtime / "custody.json",
            _reader(password),
            control_head=authority.state.head,
            secrets=body_secrets,
        )
        EncryptedKeystore.create(
            runtime / "transport-custody.json",
            _reader(password),
            control_head=authority.state.head,
            secrets=transport_secrets,
        )
        _private_write(runtime / "runtime.json", bundle)
        _private_write(
            runtime / "client.json",
            _client(runtime_id, label, origin, capabilities[OBSERVE_PROFILE]),
        )
        _private_write(
            runtime / "client.key",
            body_secrets[slots["operator_capabilities"][OBSERVE_PROFILE]],
        )
        for name in OPERATOR_PROFILE_NAMES:
            if name == OBSERVE_PROFILE:
                continue
            role = operator_clients / name
            role.mkdir(mode=0o700)
            _private_write(
                role / "client.json",
                _client(runtime_id, label, origin, capabilities[name]),
            )
            _private_write(
                role / "capability.key",
                body_secrets[slots["operator_capabilities"][name]],
            )
            _fsync_directory(role)
        for name in HOST_PROFILE_NAMES:
            role = host_clients / name
            role.mkdir(mode=0o700)
            _private_write(
                role / "client.json",
                _client(runtime_id, label, origin, host_capabilities[name]),
            )
            _private_write(
                role / "capability.key",
                body_secrets[slots["host_capabilities"][name]],
            )
            _fsync_directory(role)
        authority_document = {
            "schema": "dm.operator.authority/v1",
            "control_artifacts": [copy.deepcopy(dict(genesis))],
            "control_head": authority.state.head,
            "manifest": authority.manifest.value,
            "credentials": list(authority.credentials.values()),
            "incarnations": list(authority.incarnations.values()),
        }
        _private_write(staging / "authority.json", authority_document)
        _private_write(staging / "request.json", request)
        _private_write(staging / "activation.json", verified_activation)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "activation_id": verified_activation["activation_id"],
            "request_id": verified_activation["body"]["request_id"],
            "being_ref": authority.manifest.being_ref,
            "control_head": authority.state.head,
            "manifest_hash": authority.manifest.digest,
            "origin": origin,
            "runtime_schema": bundle["schema"],
            "runtime_sha256": hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
            "empty_writable_state": True,
            "root_seeds_in_target": False,
            "capability_lifecycle": verified_preparation["capability_lifecycle"],
        }
        _private_write(staging / "receipt.json", receipt)
        _fsync_directory(operator_clients)
        _fsync_directory(host_clients)
        _fsync_directory(runtime)
        _fsync_directory(staging)
        os.replace(staging, target)
        _fsync_directory(parent)
        staging = None
        return receipt
    finally:
        password[:] = b"\x00" * len(password)
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="daimon-first-embodiment", description=__doc__
    )
    commands = result.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--genesis", type=Path, required=True)
    prepare.add_argument("--profile", type=Path, required=True)
    prepare.add_argument("--password-fd", type=int, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    share = commands.add_parser("root-share")
    share.add_argument("--genesis", type=Path, required=True)
    share.add_argument("--request", type=Path, required=True)
    share.add_argument("--holder", type=Path, required=True)
    share.add_argument("--password-fd", type=int, required=True)
    share.add_argument("--output", type=Path, required=True)
    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--genesis", type=Path, required=True)
    aggregate.add_argument("--request", type=Path, required=True)
    aggregate.add_argument("--share", type=Path, action="append", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--genesis", type=Path, required=True)
    activate.add_argument("--preparation-dir", type=Path, required=True)
    activate.add_argument("--request", type=Path, required=True)
    activate.add_argument("--activation", type=Path, required=True)
    activate.add_argument("--password-fd", type=int, required=True)
    activate.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    passwords: list[bytearray] = []
    try:
        genesis = _document(arguments.genesis, "first_embodiment_genesis_unavailable")
        if arguments.command == "prepare":
            password = _password(arguments.password_fd)
            passwords.append(password)
            profile = _document(
                arguments.profile, "first_embodiment_profile_unavailable"
            )
            receipt = prepare_target(
                arguments.output,
                genesis,
                profile,
                _reader(password),
                created_at_ms=time.time_ns() // 1_000_000,
            )
        elif arguments.command == "root-share":
            password = _password(arguments.password_fd)
            passwords.append(password)
            request = _document(
                arguments.request, "first_embodiment_request_unavailable"
            )
            receipt = create_root_share(
                genesis,
                request,
                arguments.holder,
                _reader(password),
                observed_at_ms=time.time_ns() // 1_000_000,
            )
            _write_new(arguments.output, receipt)
        elif arguments.command == "aggregate":
            request = _document(
                arguments.request, "first_embodiment_request_unavailable"
            )
            receipt = aggregate_activation(
                genesis,
                request,
                [
                    _document(path, "first_embodiment_share_unavailable")
                    for path in arguments.share
                ],
                observed_at_ms=time.time_ns() // 1_000_000,
            )
            _write_new(arguments.output, receipt)
        else:
            password = _password(arguments.password_fd)
            passwords.append(password)
            request = _document(
                arguments.request, "first_embodiment_request_unavailable"
            )
            activation = _document(
                arguments.activation, "first_embodiment_activation_unavailable"
            )
            preparation = _document(
                arguments.preparation_dir / "preparation.json",
                "first_embodiment_preparation_unavailable",
            )
            receipt = activate_runtime(
                arguments.output,
                genesis,
                arguments.preparation_dir,
                preparation,
                request,
                activation,
                _reader(password),
            )
        print(canonical_bytes(receipt).decode("utf-8"))
        return 0
    except (
        FirstEmbodimentError,
        RebirthError,
        OSError,
        TypeError,
        ValueError,
    ) as exception:
        print(f"daimon-first-embodiment: {exception}", file=sys.stderr)
        return 2
    finally:
        for password in passwords:
            password[:] = b"\x00" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())
