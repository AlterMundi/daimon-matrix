"""Mandatory, owner-installed release authority for every inter-daimon effect.

The controller is deliberately not a model-facing API.  Native stores borrow their
already-open ``BEGIN IMMEDIATE`` transaction when admitting an obligation.  The
single process fence covers current-authority revalidation, issuance of a typed
one-call permit, and consumption at the external effect boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol, TypeVar

from .canonical import canonical_bytes
from .mandatory_echo import (
    EchoError,
    EchoJournal,
    EchoTransport,
    MandatoryEcho,
    RetryDecision,
    validate_policy,
)
from .telegram_mirror import PlainTelegramTransport


class NativeEgressError(ValueError):
    """Stable, bounded failure without native bytes, projection text, or secrets."""


class SyntheticEchoTransport:
    """Deterministic external-network double for synthetic drivers and unit tests."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def send(self, request: dict[str, Any]) -> bytes:
        snapshot = json.loads(json.dumps(request))
        self.requests.append(snapshot)
        message = {
            "message_id": len(self.requests),
            "date": 1,
            "chat": {"id": -100137, "type": "supergroup"},
            "from": {"id": 137, "is_bot": True, "first_name": "DM137"},
            "text": snapshot["text"],
        }
        return json.dumps(
            {"ok": True, "result": message}, separators=(",", ":")
        ).encode()


def synthetic_visibility(*, clock: Callable[[], int]) -> MandatoryEgressController:
    """Construct the real controller with a deterministic Telegram network double."""

    return MandatoryEgressController(
        policy={
            "schema": "daimon-visibility-policy/v2",
            "generation": 1,
            "origin": "synthetic-driver",
            "bot_id": 137,
            "chat_id": -100137,
            "topic_id": None,
            "representation": "plain-json/v2",
            "acceptance_digest": "d" * 64,
            "proof_key_id": "synthetic-only",
        },
        proof_key=b"\x89" * 32,
        transport=SyntheticEchoTransport(),
        clock=clock,
        catalog_mode="synthetic",
    )


def closed_visibility(
    *,
    clock: Callable[[], int],
    catalog_mode: Literal["validate", "migrate"] = "validate",
) -> MandatoryEgressController:
    """Fail-closed composition; migration mode may install schema but never release."""

    return MandatoryEgressController(
        policy={
            "schema": "daimon-visibility-policy/v2",
            "generation": 1,
            "origin": "receive-only",
            "bot_id": 1,
            "chat_id": -1,
            "topic_id": None,
            "representation": "plain-json/v2",
            "acceptance_digest": "0" * 64,
            "proof_key_id": "unavailable",
        },
        proof_key=b"\0" * 32,
        transport=None,
        clock=clock,
        catalog_mode=catalog_mode,
    )


def _owner_file(path: Path, *, maximum: int) -> bytes:
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) & 0o077
                or opened.st_nlink != 1
                or not 0 < opened.st_size <= maximum
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise ValueError
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ) or after.st_nlink != 1:
                raise ValueError
        finally:
            os.close(descriptor)
        if not 0 < len(raw) <= maximum or len(raw) != opened.st_size:
            raise ValueError
        return raw
    except (OSError, ValueError):
        raise NativeEgressError("egress_installation_invalid") from None


OwnerBindingVerifier = Callable[[object, object], None]
ParticipantBindingVerifier = Callable[[str, object, object], None]

_SAFE_LEAF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _closed(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError
    return value


def _sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError
    return value


def _strict_document(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ValueError
    return value


def _binding_actor(binding: object, document_sha256: str) -> tuple[str, str]:
    row = _closed(binding, {"schema", "body", "signature"})
    if row["schema"] != "dm.messaging.operator-binding/v1":
        raise ValueError
    body = row["body"]
    if (
        not isinstance(body, dict)
        or body.get("application_sha256") != document_sha256
        or not isinstance(body.get("being_ref"), str)
        or not isinstance(body.get("runtime_id"), str)
    ):
        raise ValueError
    return body["being_ref"], body["runtime_id"]


def load_owner_visibility(
    installation: Mapping[str, Any],
    *,
    directory: Path,
    expected_application_sha256: str,
    verify_owner_binding: OwnerBindingVerifier,
    verify_participant_binding: ParticipantBindingVerifier,
    clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    catalog_mode: Literal["validate", "migrate"] = "validate",
) -> MandatoryEgressController:
    """Verify one closed signed installation and construct an offline controller."""

    try:
        envelope = _closed(dict(installation), {"document", "binding"})
        document = _closed(
            envelope["document"],
            {
                "schema",
                "generation",
                "runtime_id",
                "application_sha256",
                "disclosure",
                "acceptance_set",
                "policy",
                "secrets",
                "telegram_qualification",
            },
        )
        if (
            document["schema"] != "dm.messaging.visibility-installation/v1"
            or type(document["generation"]) is not int
            or not 0 < document["generation"] < 2**52
            or not isinstance(document["runtime_id"], str)
            or not document["runtime_id"]
            or _sha256(document["application_sha256"])
            != _sha256(expected_application_sha256)
        ):
            raise ValueError
        installation_sha256 = _digest(canonical_bytes(document))
        verify_owner_binding(document, envelope["binding"])
        owner_actor, owner_runtime_id = _binding_actor(
            envelope["binding"], installation_sha256
        )
        if owner_runtime_id != document["runtime_id"]:
            raise ValueError

        disclosure = _closed(
            document["disclosure"],
            {
                "schema",
                "issued_at_ms",
                "destination",
                "scope",
                "scope_sha256",
                "participants",
                "risk",
            },
        )
        destination = _closed(
            disclosure["destination"],
            {"bot_id", "chat_id", "topic_id", "representation"},
        )
        scope = _closed(disclosure["scope"], {"mode", "channels", "projected_content"})
        channels = scope["channels"]
        participants = disclosure["participants"]
        if (
            disclosure["schema"] != "dm.messaging.visibility-disclosure/v1"
            or type(disclosure["issued_at_ms"]) is not int
            or not 0 <= disclosure["issued_at_ms"] < 2**52
            or disclosure["scope_sha256"] != _digest(canonical_bytes(scope))
            or scope["mode"] != "all-inter-daimon-communications"
            or scope["projected_content"] != "complete-plaintext-content-and-metadata"
            or not isinstance(channels, list)
            or not channels
            or not isinstance(participants, list)
            or participants != sorted(set(participants))
            or owner_actor not in participants
            or disclosure["risk"]
            != "all-inter-daimon-communication-will-be-posted-as-plaintext-"
            "to-the-fixed-telegram-destination"
        ):
            raise ValueError
        disclosed_participants: set[str] = set()
        for channel in channels:
            channel = _closed(
                channel,
                {
                    "channel_id",
                    "direction",
                    "local_being_ref",
                    "peer_being_ref",
                    "bootstrap_policy",
                    "relationship_disclosure",
                },
            )
            if (
                not isinstance(channel["channel_id"], str)
                or not channel["channel_id"]
                or channel["direction"] not in {"incoming", "outgoing"}
                or not isinstance(channel["bootstrap_policy"], dict)
                or not isinstance(channel["relationship_disclosure"], dict)
            ):
                raise ValueError
            for name in ("local_being_ref", "peer_being_ref"):
                if not isinstance(channel[name], str) or not channel[name]:
                    raise ValueError
                disclosed_participants.add(channel[name])
        if disclosed_participants != set(participants):
            raise ValueError

        acceptance_set = _closed(
            document["acceptance_set"],
            {"schema", "disclosure_sha256", "bindings"},
        )
        disclosure_sha256 = _digest(canonical_bytes(disclosure))
        bindings = acceptance_set["bindings"]
        if (
            acceptance_set["schema"] != "dm.messaging.visibility-acceptance-set/v1"
            or acceptance_set["disclosure_sha256"] != disclosure_sha256
            or not isinstance(bindings, list)
            or len(bindings) != len(participants)
        ):
            raise ValueError
        binding_actors = []
        for participant, binding in zip(participants, bindings, strict=True):
            actor, _runtime_id = _binding_actor(binding, disclosure_sha256)
            if actor != participant:
                raise ValueError
            verify_participant_binding(participant, disclosure, binding)
            binding_actors.append(actor)
        if binding_actors != participants:
            raise ValueError

        policy = _closed(
            document["policy"],
            {
                "schema",
                "generation",
                "origin",
                "bot_id",
                "chat_id",
                "topic_id",
                "representation",
                "acceptance_digest",
                "proof_key_id",
            },
        )
        validate_policy(policy)
        if (
            policy["generation"] != document["generation"]
            or policy["acceptance_digest"] != _digest(canonical_bytes(acceptance_set))
            or any(
                destination[name] != policy[name]
                for name in ("bot_id", "chat_id", "topic_id", "representation")
            )
        ):
            raise ValueError

        secrets = _closed(
            document["secrets"],
            {"telegram_token_file", "telegram_token_sha256", "proof_key_file"},
        )
        for name in ("telegram_token_file", "proof_key_file"):
            if (
                not isinstance(secrets[name], str)
                or _SAFE_LEAF.fullmatch(secrets[name]) is None
            ):
                raise ValueError
        token_raw = _owner_file(directory / secrets["telegram_token_file"], maximum=160)
        proof_key = _owner_file(directory / secrets["proof_key_file"], maximum=32)
        token_sha256 = _digest(token_raw)
        if (
            secrets["telegram_token_sha256"] != token_sha256
            or len(proof_key) != 32
            or policy["proof_key_id"] != "sha256:" + _digest(proof_key)
        ):
            raise ValueError
        token = token_raw.decode("ascii")
        if token.split(":", 1)[0] != str(policy["bot_id"]):
            raise ValueError

        qualification = _closed(
            document["telegram_qualification"],
            {
                "schema",
                "qualified_at_ms",
                "token_sha256",
                "get_me_bot_id",
                "probe_chat_id",
                "probe_topic_id",
                "probe_message_id",
                "probe_text_sha256",
            },
        )
        if (
            qualification["schema"] != "dm.messaging.telegram-qualification/v1"
            or type(qualification["qualified_at_ms"]) is not int
            or not 0 <= qualification["qualified_at_ms"] < 2**52
            or qualification["token_sha256"] != token_sha256
            or qualification["get_me_bot_id"] != policy["bot_id"]
            or qualification["probe_chat_id"] != policy["chat_id"]
            or qualification["probe_topic_id"] != policy["topic_id"]
            or type(qualification["probe_message_id"]) is not int
            or qualification["probe_message_id"] <= 0
        ):
            raise ValueError
        _sha256(qualification["probe_text_sha256"])
        transport = PlainTelegramTransport(
            token=token,
            bot_id=policy["bot_id"],
            chat_id=policy["chat_id"],
            topic_id=policy["topic_id"],
        )
        return MandatoryEgressController(
            policy=policy,
            proof_key=proof_key,
            transport=transport,
            clock=clock,
            catalog_mode=catalog_mode,
            installation_digest=installation_sha256,
            owner_actor=owner_actor,
            verify_owner_binding=verify_owner_binding,
        )
    except NativeEgressError:
        raise
    except Exception:
        raise NativeEgressError("egress_installation_invalid") from None


def load_owner_visibility_file(
    path: Path,
    *,
    expected_application_sha256: str | None = None,
    verify_owner_binding: OwnerBindingVerifier | None = None,
    verify_participant_binding: ParticipantBindingVerifier | None = None,
    clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    catalog_mode: Literal["validate", "migrate"] = "validate",
) -> MandatoryEgressController:
    """Load a canonical owner-signed installation; missing verifiers fail closed."""

    try:
        if (
            expected_application_sha256 is None
            or verify_owner_binding is None
            or verify_participant_binding is None
        ):
            raise ValueError
        installation = _strict_document(_owner_file(path, maximum=64 * 1024))
    except Exception:
        raise NativeEgressError("egress_installation_invalid") from None
    return load_owner_visibility(
        installation,
        directory=path.parent,
        expected_application_sha256=expected_application_sha256,
        verify_owner_binding=verify_owner_binding,
        verify_participant_binding=verify_participant_binding,
        clock=clock,
        catalog_mode=catalog_mode,
    )


# One being's own `/we` lane: scope resolution and state convergence between its
# embodiments. These paths never carry an inter-daimon logical message, so the
# mandatory inter-daimon mirror does not apply to them. The lane is not a bypass
# flag: it is derived from the catalog's own authoritative store tables, it stays
# authorized and digest-bound, every operation is still journaled with a release
# count, and every event remains in the being's ledger where an operator can read
# it on request. Inter-daimon message and evidence egress keeps its confirmed echo.
INTRA_BEING_LANE_PATHS: Final[frozenset[str]] = frozenset(
    {
        "peer-scope-request",
        "peer-sync-request",
        "peer-scope-response",
        "peer-sync-response",
    }
)

PEER_EGRESS_PATHS: Final[frozenset[str]] = frozenset(
    {
        "route-provider-request",
        "messaging-evidence-request",
        "messaging-message-request",
        "messaging-evidence-result",
        "messaging-message-result",
        "peer-scope-request",
        "peer-sync-request",
        "peer-scope-response",
        "peer-sync-response",
    }
)

OPERATION_TABLE_SQL: Final = (
    "CREATE TABLE mandatory_egress_operations ("
    "operation_id TEXT PRIMARY KEY, path_id TEXT NOT NULL, locator TEXT NOT NULL, "
    "native_sha256 TEXT NOT NULL, projection_json BLOB NOT NULL, "
    "projection_sha256 TEXT NOT NULL, echo_operation_id TEXT NOT NULL UNIQUE, "
    "echo_binding_digest TEXT NOT NULL, deadline_ms INTEGER NOT NULL, "
    "authority_head TEXT NOT NULL, created_at_ms INTEGER NOT NULL, "
    "release_count INTEGER NOT NULL DEFAULT 0)"
)
VISIBILITY_SCHEMA_VERSION: Final = 1


@dataclass(frozen=True)
class OperationBinding:
    """Durable exact-operation reference returned by an authoritative store."""

    catalog_id: str
    path_id: str
    operation_id: str
    locator: str
    native_sha256: str
    projection_sha256: str
    echo_operation_id: str
    echo_binding_digest: str
    deadline_ms: int
    authority_head: str


def verify_echo_retry_command(
    raw: bytes,
    *,
    installation_sha256: str,
    policy_sha256: str,
    operation: OperationBinding,
    latest_attempt_id: str,
    owner_actor: str,
    at_ms: int,
    verify_owner_binding: OwnerBindingVerifier,
) -> RetryDecision:
    """Verify one current owner command over the exact ambiguous native effect."""

    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 8192:
            raise ValueError
        envelope = _closed(_strict_document(raw), {"command", "binding"})
        command = _closed(
            envelope["command"],
            {
                "schema",
                "resolution",
                "visibility_installation_sha256",
                "policy_sha256",
                "catalog_id",
                "path_id",
                "native_operation_id",
                "decision",
            },
        )
        decision = _closed(
            command["decision"],
            {
                "authorization_id",
                "actor",
                "operation_id",
                "binding_digest",
                "attempt_id",
                "approved_at_ms",
                "expires_at_ms",
                "risk",
            },
        )
        verify_owner_binding(command, envelope["binding"])
        actor, _runtime_id = _binding_actor(
            envelope["binding"], _digest(canonical_bytes(command))
        )
        authorization_id = uuid.UUID(decision["authorization_id"])
        if (
            command["schema"] != "dm.messaging.echo-retry-command/v1"
            or command["resolution"] != "retry-ambiguous"
            or command["visibility_installation_sha256"] != installation_sha256
            or command["policy_sha256"] != policy_sha256
            or command["catalog_id"] != operation.catalog_id
            or command["path_id"] != operation.path_id
            or command["native_operation_id"] != operation.operation_id
            or actor != owner_actor
            or decision["actor"] != owner_actor
            or decision["operation_id"] != operation.echo_operation_id
            or decision["binding_digest"] != operation.echo_binding_digest
            or decision["attempt_id"] != latest_attempt_id
            or str(authorization_id) != decision["authorization_id"]
            or authorization_id.version != 4
            or type(decision["approved_at_ms"]) is not int
            or type(decision["expires_at_ms"]) is not int
            or not 0 <= decision["approved_at_ms"] < 2**52
            or not 0 <= decision["expires_at_ms"] < 2**52
            or not decision["approved_at_ms"] <= at_ms < decision["expires_at_ms"]
            or decision["expires_at_ms"] - decision["approved_at_ms"] > 60_000
            or decision["risk"] != "duplicate-platform-post-accepted"
        ):
            raise ValueError
        return RetryDecision(**decision)
    except Exception:
        raise NativeEgressError("egress_retry_unauthorized") from None


class _PermitMarker:
    pass


@dataclass(frozen=True)
class ReleasePermit:
    """Process-local one-call authority; only the controller can create/consume it."""

    binding: OperationBinding
    nonce: str
    _marker: _PermitMarker


class NativeResolver(Protocol):
    def __call__(self, locator: str) -> bytes: ...


class CurrentAuthority(Protocol):
    def __call__(self, binding: OperationBinding) -> bool: ...


@dataclass(frozen=True)
class _Catalog:
    catalog_id: str
    path: Path
    identity: tuple[int, int]
    resolve: NativeResolver
    authorize: CurrentAuthority


@dataclass(frozen=True)
class _NativeHistory:
    operation_id: str
    locator: str
    native_sha256: str
    path_id: str | None = None


_Result = TypeVar("_Result")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _projection_bytes(projection: Mapping[str, Any]) -> bytes:
    return canonical_bytes(dict(projection))


def native_projection(
    *,
    operation_id: str,
    native: bytes,
    sender: str,
    recipient: str,
    thread_id: str,
    kind: str,
    stage: str,
) -> dict[str, Any]:
    """Build the closed projection used for non-message native effects."""

    return {
        "event_id": operation_id,
        "event_digest": _digest(native),
        "sender": sender,
        "recipients": [recipient],
        "thread_id": thread_id,
        "reply_to": None,
        "kind": kind,
        "content": {"stage": stage},
    }


def _valid_text(value: str, *, maximum: int = 256) -> bool:
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= maximum


class MandatoryEgressController:
    """One shared mandatory-visibility controller and one process-wide fence."""

    def __init__(
        self,
        *,
        policy: Mapping[str, Any],
        proof_key: bytes,
        transport: EchoTransport | None,
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
        catalog_mode: Literal["validate", "migrate", "synthetic"] = "validate",
        installation_digest: str | None = None,
        owner_actor: str | None = None,
        verify_owner_binding: OwnerBindingVerifier | None = None,
    ) -> None:
        if not isinstance(proof_key, bytes) or len(proof_key) != 32:
            raise NativeEgressError("egress_proof_key_invalid")
        self._policy = json.loads(json.dumps(dict(policy)))
        self._proof_key = bytes(proof_key)
        self._transport = transport
        self._clock = clock
        if any(
            value is not None
            for value in (installation_digest, owner_actor, verify_owner_binding)
        ) and (
            not isinstance(installation_digest, str)
            or _SHA256.fullmatch(installation_digest) is None
            or not isinstance(owner_actor, str)
            or not owner_actor
            or verify_owner_binding is None
        ):
            raise NativeEgressError("egress_installation_invalid")
        self._installation_digest = installation_digest
        self._owner_actor = owner_actor
        self._verify_owner_binding = verify_owner_binding
        if catalog_mode not in {"validate", "migrate", "synthetic"}:
            raise NativeEgressError("egress_catalog_mode_invalid")
        self._catalog_mode: Literal["validate", "migrate", "synthetic"] = catalog_mode
        self._fence = threading.Lock()
        self._catalogs: dict[str, _Catalog] = {}
        self._paths: dict[str, set[str]] = {}
        self._registry_closed = False
        self._validated_paths: frozenset[str] | None = None
        self._permit_marker = _PermitMarker()
        self._live_permits: set[str] = set()
        self._worker_lock = threading.Lock()
        self._worker_state = "stopped"
        self._worker_failures = 0

    @property
    def policy_digest(self) -> str:
        return _digest(canonical_bytes(self._policy))

    @property
    def installation_digest(self) -> str:
        if self._installation_digest is None:
            raise NativeEgressError("egress_recovery_unavailable")
        return self._installation_digest

    @property
    def owner_actor(self) -> str:
        if self._owner_actor is None:
            raise NativeEgressError("egress_recovery_unavailable")
        return self._owner_actor

    @property
    def release_enabled(self) -> bool:
        """True only for an owner-installed or explicit synthetic transport."""

        return self._transport is not None

    @property
    def catalog_mode(self) -> Literal["validate", "migrate", "synthetic"]:
        """Expose the immutable composition mode to trusted offline orchestration."""

        return self._catalog_mode

    def registered_catalog_ids(self) -> frozenset[str]:
        """Return identifiers only; paths and native locators remain private."""

        return frozenset(self._catalogs)

    def register_catalog(
        self,
        *,
        catalog_id: str,
        path: Path,
        resolve: NativeResolver,
        authorize: CurrentAuthority,
    ) -> None:
        """Register one authoritative catalog and provision its owned echo subset.

        Production callers invoke this only while holding the owner runtime lock,
        before listeners are bound.  Fresh synthetic catalogs use the same path.
        Existing incompatible catalogs fail closed; no row is repaired or reset.
        """

        if (
            self._registry_closed
            or not _valid_text(catalog_id, maximum=128)
            or not callable(resolve)
            or not callable(authorize)
        ):
            raise NativeEgressError("egress_catalog_invalid")
        absolute = path.absolute()
        existing = self._catalogs.get(catalog_id)
        if existing is not None:
            try:
                identity = self._path_identity(absolute)
            except OSError:
                raise NativeEgressError("egress_catalog_invalid") from None
            if existing.path != absolute and (
                existing.path.exists() or existing.identity != identity
            ):
                raise NativeEgressError("egress_catalog_invalid")
            self._catalogs[catalog_id] = _Catalog(
                catalog_id=catalog_id,
                path=absolute,
                identity=identity,
                resolve=resolve,
                authorize=authorize,
            )
            return
        if any(item.path == absolute for item in self._catalogs.values()):
            raise NativeEgressError("egress_catalog_invalid")
        self._catalogs[catalog_id] = _Catalog(
            catalog_id=catalog_id,
            path=absolute,
            identity=self._path_identity(absolute),
            resolve=resolve,
            authorize=authorize,
        )

    def register_path(self, path_id: str, catalog_id: str) -> None:
        if (
            self._registry_closed
            or path_id not in PEER_EGRESS_PATHS
            or catalog_id not in self._catalogs
        ):
            raise NativeEgressError("egress_path_registry_invalid")
        self._paths.setdefault(path_id, set()).add(catalog_id)
        catalog = self._catalogs[catalog_id]
        self._prepare_catalog(catalog.path, catalog_id)

    def _prepare_catalog(self, path: Path, catalog_id: str) -> None:
        if self._catalog_mode == "synthetic":
            self._provision(path, catalog_id, reconcile=False)
        elif self._catalog_mode == "validate":
            self._validate_catalog(path, catalog_id)

    def migrate_catalog(self, *, catalog_id: str, path: Path, version: int) -> None:
        """Explicitly install one versioned visibility journal under owner lock."""

        if (
            self._catalog_mode != "migrate"
            or self._registry_closed
            or version != VISIBILITY_SCHEMA_VERSION
        ):
            raise NativeEgressError("egress_migration_not_authorized")
        absolute = path.absolute()
        catalog = self._catalogs.get(catalog_id)
        if catalog is None or catalog.path != absolute:
            raise NativeEgressError("egress_migration_not_authorized")
        self._path_identity(absolute)
        self._preflight_migration(absolute, catalog_id)
        self._provision(absolute, catalog_id)

    def migrate_registered_catalogs(
        self,
        catalog_ids: frozenset[str] | None = None,
        *,
        version: int,
    ) -> None:
        """Migrate selected registered catalogs; each catalog retry is idempotent."""

        if (
            self._catalog_mode != "migrate"
            or self._registry_closed
            or version != VISIBILITY_SCHEMA_VERSION
        ):
            raise NativeEgressError("egress_migration_not_authorized")
        selected = frozenset(self._catalogs) if catalog_ids is None else catalog_ids
        if not selected <= self._catalogs.keys():
            raise NativeEgressError("egress_migration_not_authorized")
        for catalog_id in sorted(selected):
            catalog = self._catalogs[catalog_id]
            self._preflight_migration(catalog.path, catalog_id)
        for catalog_id in sorted(selected):
            catalog = self._catalogs[catalog_id]
            self._provision(catalog.path, catalog_id)

    def validate_registered_catalogs(
        self, catalog_ids: frozenset[str] | None = None
    ) -> None:
        """Read-only validation and history reconciliation for owner ceremonies."""

        selected = frozenset(self._catalogs) if catalog_ids is None else catalog_ids
        if self._registry_closed or not selected <= self._catalogs.keys():
            raise NativeEgressError("egress_catalog_invalid")
        for catalog_id in sorted(selected):
            catalog = self._catalogs[catalog_id]
            self._validate_catalog(catalog.path, catalog_id)

    def validate_registry(self, enabled_paths: set[str]) -> None:
        if (
            not enabled_paths <= PEER_EGRESS_PATHS
            or set(self._paths) != enabled_paths
            or any(not self._paths[path] for path in enabled_paths)
        ):
            raise NativeEgressError("egress_path_registry_incomplete")
        if self._catalog_mode != "synthetic":
            for catalog_id, catalog in sorted(self._catalogs.items()):
                registered = frozenset(
                    path_id
                    for path_id, catalog_ids in self._paths.items()
                    if catalog_id in catalog_ids
                )
                try:
                    database = sqlite3.connect(
                        catalog.path.as_uri() + "?mode=ro&immutable=1", uri=True
                    )
                    try:
                        expected = self._authoritative_paths(database)
                    finally:
                        database.close()
                except NativeEgressError:
                    raise
                except Exception:
                    raise NativeEgressError("egress_path_registry_incomplete") from None
                if registered != expected:
                    raise NativeEgressError("egress_path_registry_incomplete")
                self._validate_catalog(catalog.path, catalog_id)
        self._validated_paths = frozenset(enabled_paths)
        self._registry_closed = True

    def worker_started(self) -> None:
        with self._worker_lock:
            if self._worker_state != "stopped":
                raise NativeEgressError("egress_worker_already_started")
            self._worker_state = "running"

    def worker_succeeded(self) -> None:
        with self._worker_lock:
            if self._worker_state == "stopped":
                raise NativeEgressError("egress_worker_not_started")
            self._worker_state = "running"

    def worker_failed(self) -> None:
        with self._worker_lock:
            if self._worker_state == "stopped":
                raise NativeEgressError("egress_worker_not_started")
            self._worker_state = "degraded"
            self._worker_failures += 1

    def worker_stopped(self) -> None:
        with self._worker_lock:
            self._worker_state = "stopped"

    @contextmanager
    def _database(self, catalog: _Catalog) -> Iterator[sqlite3.Connection]:
        database = sqlite3.connect(catalog.path, isolation_level=None, timeout=30)
        try:
            database.row_factory = sqlite3.Row
            mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            database.execute("PRAGMA synchronous=FULL")
            if (
                str(mode).lower() != "delete"
                or database.execute("PRAGMA synchronous").fetchone()[0] != 2
            ):
                raise NativeEgressError("egress_storage_unavailable")
            yield database
        except sqlite3.Error:
            raise NativeEgressError("egress_storage_unavailable") from None
        finally:
            database.close()

    @staticmethod
    def _schema_tokens(sql: str) -> list[str]:
        return re.findall(r"'(?:''|[^'])*'|\w+|[^\s]", sql)

    @staticmethod
    def _table_names(database: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in database.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            ).fetchall()
        }

    def _validate_visibility_schema(
        self, database: sqlite3.Connection, catalog_id: str
    ) -> EchoJournal:
        names = self._table_names(database)
        expected_names = {
            "mandatory_egress_operations",
            "echo_v2_catalog",
            "echo_v2_obligations",
        }
        visibility_names = {
            name
            for name in names
            if name.startswith("mandatory_egress_") or name.startswith("echo_v2_")
        }
        if visibility_names != expected_names:
            raise NativeEgressError("egress_catalog_invalid")
        row = database.execute(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?",
            ("mandatory_egress_operations",),
        ).fetchone()
        if (
            row is None
            or row[0] is None
            or self._schema_tokens(str(row[0]))
            != self._schema_tokens(OPERATION_TABLE_SQL)
        ):
            raise NativeEgressError("egress_catalog_invalid")
        try:
            return EchoJournal(
                database,
                catalog_id=catalog_id,
                authentication_key=self._proof_key,
            )
        except EchoError as exception:
            raise NativeEgressError("egress_catalog_invalid") from exception

    @classmethod
    def _authoritative_paths(cls, database: sqlite3.Connection) -> frozenset[str]:
        names = cls._table_names(database)
        mappings = {
            "communication_egress_requests": frozenset({"route-provider-request"}),
            "peer_exchanges": frozenset({"peer-scope-response", "peer-sync-response"}),
            "messaging_transport_stages": frozenset(
                {"messaging-evidence-request", "messaging-message-request"}
            ),
            "inbox_requests": frozenset(
                {"messaging-evidence-result", "messaging-message-result"}
            ),
        }
        matches = [paths for table, paths in mappings.items() if table in names]
        if "peer_outbox" in names or "peer_outbox_carriers" in names:
            matches.append(frozenset({"peer-scope-request", "peer-sync-request"}))
        if len(matches) != 1:
            raise NativeEgressError("egress_catalog_invalid")
        return matches[0]

    def _native_history(
        self, database: sqlite3.Connection, catalog_id: str
    ) -> dict[str, _NativeHistory]:
        """Read the authoritative native operation inventory for one known store."""

        names = self._table_names(database)
        allowed_paths = {
            path_id
            for path_id, catalog_ids in self._paths.items()
            if catalog_id in catalog_ids
        }
        authoritative_paths = self._authoritative_paths(database)
        if not allowed_paths or not allowed_paths <= authoritative_paths:
            raise NativeEgressError("egress_catalog_invalid")
        histories: list[list[_NativeHistory]] = []
        if "communication_egress_requests" in names:
            histories.append(
                [
                    _NativeHistory(
                        operation_id=str(row[0]),
                        locator=str(row[0]),
                        native_sha256=self._verified_native_digest(row[1], row[2]),
                        path_id="route-provider-request",
                    )
                    for row in database.execute(
                        "SELECT attempt_id, request, request_sha256 "
                        "FROM communication_egress_requests ORDER BY attempt_id"
                    )
                ]
            )
        if "peer_outbox" in names:
            carrier_count = (
                database.execute(
                    "SELECT count(*) FROM peer_outbox_carriers"
                ).fetchone()[0]
                if "peer_outbox_carriers" in names
                else 0
            )
            if carrier_count:
                uncovered = database.execute(
                    "SELECT count(*) FROM peer_outbox AS logical "
                    "WHERE NOT EXISTS ("
                    "SELECT 1 FROM peer_outbox_carriers AS carrier "
                    "WHERE carrier.logical_request_id=logical.request_id)"
                ).fetchone()[0]
                if uncovered:
                    raise NativeEgressError("egress_historical_obligation_inconsistent")
                histories.append(
                    [
                        _NativeHistory(
                            operation_id=str(row[0]),
                            locator=str(row[0]),
                            native_sha256=self._verified_native_digest(row[1], row[2]),
                            path_id=str(row[3]),
                        )
                        for row in database.execute(
                            "SELECT egress_operation_id, request, request_sha256, "
                            "egress_path_id FROM peer_outbox_carriers "
                            "ORDER BY egress_operation_id"
                        )
                    ]
                )
            else:
                histories.append(
                    [
                        _NativeHistory(
                            operation_id=str(row[0]),
                            locator=str(row[0]),
                            native_sha256=self._verified_native_digest(row[1], row[2]),
                        )
                        for row in database.execute(
                            "SELECT request_id, request, request_sha256 "
                            "FROM peer_outbox ORDER BY request_id"
                        )
                    ]
                )
        if "peer_exchanges" in names:
            histories.append(
                [
                    _NativeHistory(
                        operation_id=str(row[0]),
                        locator=str(row[0]),
                        native_sha256=self._verified_native_digest(row[1], row[2]),
                        path_id=str(row[3]),
                    )
                    for row in database.execute(
                        "SELECT envelope_id, response, response_sha256, "
                        "egress_path_id FROM peer_exchanges WHERE state='responded' "
                        "ORDER BY envelope_id"
                    )
                ]
            )
        if "messaging_transport_stages" in names:
            histories.append(
                [
                    _NativeHistory(
                        operation_id=f"{row[1]}:{row[2]}",
                        locator="\0".join((str(row[0]), str(row[1]), str(row[2]))),
                        native_sha256=self._verified_native_digest(row[3], row[4]),
                        path_id=f"messaging-{row[2]}-request",
                    )
                    for row in database.execute(
                        "SELECT owner, send_id, phase, request, request_sha256 "
                        "FROM messaging_transport_stages ORDER BY owner, send_id, phase"
                    )
                ]
            )
        if "inbox_requests" in names:
            histories.append(
                [
                    _NativeHistory(
                        operation_id=str(row[0]),
                        locator=str(row[0]),
                        native_sha256=self._verified_native_digest(row[1], row[2]),
                        path_id=str(row[3]),
                    )
                    for row in database.execute(
                        "SELECT request_id, response, response_sha256, egress_path_id "
                        "FROM inbox_requests WHERE response IS NOT NULL "
                        "ORDER BY request_id"
                    )
                ]
            )
        if len(histories) != 1:
            raise NativeEgressError("egress_catalog_invalid")
        rows = histories[0]
        result = {row.operation_id: row for row in rows}
        if len(result) != len(rows):
            raise NativeEgressError("egress_historical_obligation_inconsistent")
        return result

    @staticmethod
    def _verified_native_digest(raw: Any, stored_digest: Any) -> str:
        if not isinstance(raw, bytes) or not isinstance(stored_digest, str):
            raise NativeEgressError("egress_historical_obligation_inconsistent")
        digest = _digest(raw)
        if digest != stored_digest:
            raise NativeEgressError("egress_historical_obligation_inconsistent")
        return digest

    def _reconcile_catalog(
        self,
        database: sqlite3.Connection,
        catalog_id: str,
        journal: EchoJournal,
    ) -> None:
        native = self._native_history(database, catalog_id)
        rows = database.execute(
            "SELECT * FROM mandatory_egress_operations ORDER BY operation_id"
        ).fetchall()
        operations = {str(row["operation_id"]): row for row in rows}
        if native.keys() - operations.keys():
            raise NativeEgressError("egress_historical_obligation_missing")
        if operations.keys() != native.keys() or len(operations) != len(rows):
            raise NativeEgressError("egress_historical_obligation_inconsistent")
        allowed_paths = self._authoritative_paths(database)
        echo_ids: set[str] = set()
        for operation_id, history in native.items():
            row = operations[operation_id]
            path_id = str(row["path_id"])
            projection_raw = row["projection_json"]
            if (
                path_id not in allowed_paths
                or (history.path_id is not None and path_id != history.path_id)
                or str(row["locator"]) != history.locator
                or str(row["native_sha256"]) != history.native_sha256
                or not isinstance(projection_raw, bytes)
                or _digest(projection_raw) != row["projection_sha256"]
                or not isinstance(row["release_count"], int)
                or int(row["release_count"]) < 0
            ):
                raise NativeEgressError("egress_historical_obligation_inconsistent")
            try:
                projection = json.loads(projection_raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise NativeEgressError(
                    "egress_historical_obligation_inconsistent"
                ) from None
            if not isinstance(projection, dict) or canonical_bytes(projection) != bytes(
                projection_raw
            ):
                raise NativeEgressError("egress_historical_obligation_inconsistent")
            expected_echo_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"dm137:{catalog_id}:{path_id}:{operation_id}",
                )
            )
            echo_id = str(row["echo_operation_id"])
            if echo_id != expected_echo_id or echo_id in echo_ids:
                raise NativeEgressError("egress_historical_obligation_inconsistent")
            echo_ids.add(echo_id)
            try:
                journal._load(echo_id, str(row["echo_binding_digest"]))
            except EchoError as exception:
                raise NativeEgressError(
                    "egress_historical_obligation_inconsistent"
                ) from exception
        retained_echo_ids = {
            str(row[0])
            for row in database.execute(
                "SELECT operation_id FROM echo_v2_obligations"
            ).fetchall()
        }
        if retained_echo_ids != echo_ids:
            raise NativeEgressError("egress_historical_obligation_inconsistent")

    def _preflight_migration(self, path: Path, catalog_id: str) -> None:
        """Prove every selected catalog is safe before any catalog receives DDL."""

        try:
            database = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                database.row_factory = sqlite3.Row
                integrity = database.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or tuple(integrity) != ("ok",):
                    raise NativeEgressError("egress_catalog_invalid")
                names = self._table_names(database)
                expected = {
                    "mandatory_egress_operations",
                    "echo_v2_catalog",
                    "echo_v2_obligations",
                }
                visibility_names = {
                    name
                    for name in names
                    if name.startswith("mandatory_egress_")
                    or name.startswith("echo_v2_")
                }
                if not visibility_names:
                    if self._native_history(database, catalog_id):
                        raise NativeEgressError("egress_historical_obligation_missing")
                    return
                if visibility_names != expected:
                    raise NativeEgressError("egress_catalog_invalid")
                journal = self._validate_visibility_schema(database, catalog_id)
                self._reconcile_catalog(database, catalog_id, journal)
            finally:
                database.close()
        except NativeEgressError:
            raise
        except Exception:
            raise NativeEgressError("egress_catalog_invalid") from None

    def _provision(
        self, path: Path, catalog_id: str, *, reconcile: bool = True
    ) -> None:
        try:
            database = sqlite3.connect(path, isolation_level=None, timeout=30)
            try:
                database.row_factory = sqlite3.Row
                database.execute("PRAGMA journal_mode=DELETE")
                database.execute("PRAGMA synchronous=FULL")
                database.execute("BEGIN IMMEDIATE")
                names = self._table_names(database)
                expected = {
                    "mandatory_egress_operations",
                    "echo_v2_catalog",
                    "echo_v2_obligations",
                }
                visibility_names = {
                    name
                    for name in names
                    if name.startswith("mandatory_egress_")
                    or name.startswith("echo_v2_")
                }
                if not visibility_names:
                    if reconcile and self._native_history(database, catalog_id):
                        raise NativeEgressError("egress_historical_obligation_missing")
                    EchoJournal.initialize(
                        database,
                        catalog_id=catalog_id,
                        authentication_key=self._proof_key,
                    )
                    database.execute(OPERATION_TABLE_SQL)
                elif visibility_names != expected:
                    raise NativeEgressError("egress_catalog_invalid")
                journal = self._validate_visibility_schema(database, catalog_id)
                if reconcile:
                    self._reconcile_catalog(database, catalog_id, journal)
                database.commit()
            except BaseException:
                if database.in_transaction:
                    database.rollback()
                raise
            finally:
                database.close()
        except NativeEgressError:
            raise
        except Exception:
            raise NativeEgressError("egress_catalog_invalid") from None

    def _validate_catalog(self, path: Path, catalog_id: str) -> None:
        """Validate schema and exact native-history coverage read-only."""

        try:
            uri = path.as_uri() + "?mode=ro&immutable=1"
            database = sqlite3.connect(uri, uri=True)
            try:
                database.row_factory = sqlite3.Row
                integrity = database.execute("PRAGMA integrity_check").fetchone()
                if integrity is None or tuple(integrity) != ("ok",):
                    raise NativeEgressError("egress_catalog_invalid")
                journal = self._validate_visibility_schema(database, catalog_id)
                self._reconcile_catalog(database, catalog_id, journal)
            finally:
                database.close()
        except NativeEgressError:
            raise
        except Exception:
            raise NativeEgressError("egress_catalog_invalid") from None

    def admit_in_transaction(
        self,
        database: sqlite3.Connection,
        *,
        catalog_id: str,
        path_id: str,
        operation_id: str,
        locator: str,
        native_bytes: bytes,
        projection: Mapping[str, Any],
        deadline_ms: int,
        authority_head: str,
    ) -> OperationBinding:
        """Atomically join one obligation to caller-owned authoritative state."""

        if not database.in_transaction:
            raise NativeEgressError("egress_transaction_required")
        if (
            catalog_id not in self._catalogs
            or path_id not in PEER_EGRESS_PATHS
            or catalog_id not in self._paths.get(path_id, set())
            or not _valid_text(operation_id, maximum=128)
            or not _valid_text(locator, maximum=1024)
            or not isinstance(native_bytes, bytes)
            or not native_bytes
            or not isinstance(deadline_ms, int)
            or isinstance(deadline_ms, bool)
            or deadline_ms <= self._clock()
            or not _valid_text(authority_head, maximum=512)
        ):
            raise NativeEgressError("egress_operation_invalid")
        catalog = self._catalogs[catalog_id]
        if self._database_identity(database) != self._path_identity(catalog.path):
            raise NativeEgressError("egress_catalog_mismatch")
        projection_raw = _projection_bytes(projection)
        native_sha256 = _digest(native_bytes)
        projection_sha256 = _digest(projection_raw)
        echo_operation_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"dm137:{catalog_id}:{path_id}:{operation_id}",
            )
        )
        row = database.execute(
            "SELECT * FROM mandatory_egress_operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is not None:
            existing = self._binding_from_row(catalog_id, row)
            if (
                existing.path_id != path_id
                or existing.locator != locator
                or existing.native_sha256 != native_sha256
                or existing.projection_sha256 != projection_sha256
                or existing.echo_operation_id != echo_operation_id
            ):
                raise NativeEgressError("egress_operation_conflict")
            return existing
        journal = EchoJournal(
            database,
            catalog_id=catalog_id,
            authentication_key=self._proof_key,
        )
        try:
            echo_digest = journal.admit(
                echo_operation_id, dict(projection), self._policy
            )
        except EchoError as exception:
            raise NativeEgressError(str(exception)) from None
        candidate = OperationBinding(
            catalog_id=catalog_id,
            path_id=path_id,
            operation_id=operation_id,
            locator=locator,
            native_sha256=native_sha256,
            projection_sha256=projection_sha256,
            echo_operation_id=echo_operation_id,
            echo_binding_digest=echo_digest,
            deadline_ms=deadline_ms,
            authority_head=authority_head,
        )
        database.execute(
            "INSERT INTO mandatory_egress_operations "
            "(operation_id,path_id,locator,native_sha256,projection_json,"
            "projection_sha256,echo_operation_id,echo_binding_digest,deadline_ms,"
            "authority_head,created_at_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                path_id,
                locator,
                native_sha256,
                projection_raw,
                projection_sha256,
                echo_operation_id,
                echo_digest,
                deadline_ms,
                authority_head,
                self._clock(),
            ),
        )
        return candidate

    @staticmethod
    def _database_identity(database: sqlite3.Connection) -> tuple[int, int]:
        rows = database.execute("PRAGMA database_list").fetchall()
        main = next((row for row in rows if row[1] == "main"), None)
        if main is None or not main[2]:
            raise NativeEgressError("egress_catalog_mismatch")
        info = Path(main[2]).stat()
        return info.st_dev, info.st_ino

    @staticmethod
    def _path_identity(path: Path) -> tuple[int, int]:
        info = path.stat()
        return info.st_dev, info.st_ino

    @staticmethod
    def _binding_from_row(catalog_id: str, row: sqlite3.Row) -> OperationBinding:
        return OperationBinding(
            catalog_id=catalog_id,
            path_id=str(row["path_id"]),
            operation_id=str(row["operation_id"]),
            locator=str(row["locator"]),
            native_sha256=str(row["native_sha256"]),
            projection_sha256=str(row["projection_sha256"]),
            echo_operation_id=str(row["echo_operation_id"]),
            echo_binding_digest=str(row["echo_binding_digest"]),
            deadline_ms=int(row["deadline_ms"]),
            authority_head=str(row["authority_head"]),
        )

    def binding(self, catalog_id: str, operation_id: str) -> OperationBinding:
        catalog = self._catalogs.get(catalog_id)
        if catalog is None:
            raise NativeEgressError("egress_catalog_invalid")
        with self._database(catalog) as database:
            row = database.execute(
                "SELECT * FROM mandatory_egress_operations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            raise NativeEgressError("egress_operation_missing")
        return self._binding_from_row(catalog_id, row)

    def binding_for_native(
        self, native_bytes: bytes, *, allowed_paths: frozenset[str]
    ) -> OperationBinding:
        """Resolve one exact admitted native effect; ambiguity always fails closed."""

        digest = _digest(native_bytes)
        matches: list[OperationBinding] = []
        for catalog_id in sorted(self._catalogs):
            catalog = self._catalogs[catalog_id]
            with self._database(catalog) as database:
                rows = database.execute(
                    "SELECT * FROM mandatory_egress_operations "
                    "WHERE native_sha256=? ORDER BY operation_id",
                    (digest,),
                ).fetchall()
            matches.extend(
                self._binding_from_row(catalog_id, row)
                for row in rows
                if str(row["path_id"]) in allowed_paths
            )
        if len(matches) != 1:
            raise NativeEgressError("egress_operation_ambiguous")
        return matches[0]

    def release_registered(
        self,
        native_bytes: bytes,
        *,
        allowed_paths: frozenset[str],
        effect: Callable[[bytes], _Result],
    ) -> _Result:
        binding = self.binding_for_native(native_bytes, allowed_paths=allowed_paths)
        return self.release(binding, native_bytes, effect)

    def _load_projection(self, binding: OperationBinding) -> dict[str, Any]:
        catalog = self._catalogs[binding.catalog_id]
        with self._database(catalog) as database:
            row = database.execute(
                "SELECT projection_json FROM mandatory_egress_operations "
                "WHERE operation_id=?",
                (binding.operation_id,),
            ).fetchone()
        if row is None:
            raise NativeEgressError("egress_operation_missing")
        raw = bytes(row[0])
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise NativeEgressError("egress_operation_invalid") from None
        if not isinstance(value, dict) or canonical_bytes(value) != raw:
            raise NativeEgressError("egress_operation_invalid")
        return value

    def _mandatory(
        self, binding: OperationBinding, database: sqlite3.Connection
    ) -> MandatoryEcho:
        catalog = self._catalogs[binding.catalog_id]
        journal = EchoJournal(
            database,
            catalog_id=binding.catalog_id,
            authentication_key=self._proof_key,
        )
        return MandatoryEcho(
            journal,
            transport=self._transport,
            resolve=lambda _operation: self._load_projection(binding),
            authorize=lambda _record: self._authorize(binding, catalog),
            clock=self._clock,
        )

    @contextmanager
    def _retry_execution_guard(self) -> Iterator[None]:
        with self._fence:
            yield

    def _retry_mandatory(
        self, binding: OperationBinding, database: sqlite3.Connection
    ) -> MandatoryEcho:
        installation_digest = self._installation_digest
        owner_actor = self._owner_actor
        owner_verifier = self._verify_owner_binding
        if installation_digest is None or owner_actor is None or owner_verifier is None:
            raise NativeEgressError("egress_recovery_unavailable")
        catalog = self._catalogs[binding.catalog_id]
        journal = EchoJournal(
            database,
            catalog_id=binding.catalog_id,
            authentication_key=self._proof_key,
        )

        def verify_retry(
            raw: bytes, echo_binding: dict[str, Any], latest_attempt_id: str
        ) -> RetryDecision:
            if _digest(canonical_bytes(echo_binding)) != binding.echo_binding_digest:
                raise NativeEgressError("egress_retry_unauthorized")
            return verify_echo_retry_command(
                raw,
                installation_sha256=installation_digest,
                policy_sha256=self.policy_digest,
                operation=binding,
                latest_attempt_id=latest_attempt_id,
                owner_actor=owner_actor,
                at_ms=self._clock(),
                verify_owner_binding=owner_verifier,
            )

        return MandatoryEcho(
            journal,
            transport=self._transport,
            resolve=lambda _operation: self._load_projection(binding),
            authorize=lambda _record: self._authorize(binding, catalog),
            clock=self._clock,
            verify_retry=verify_retry,
            execution_guard=self._retry_execution_guard,
        )

    def _authorize(self, binding: OperationBinding, catalog: _Catalog) -> bool:
        current = self.binding(binding.catalog_id, binding.operation_id)
        if current != binding:
            return False
        try:
            native = catalog.resolve(binding.locator)
            return (
                isinstance(native, bytes)
                and _digest(native) == binding.native_sha256
                and self._clock() < binding.deadline_ms
                and catalog.authorize(binding) is True
            )
        except Exception:
            return False

    def inspect(self, binding: OperationBinding) -> dict[str, Any]:
        catalog = self._catalogs.get(binding.catalog_id)
        if catalog is None:
            raise NativeEgressError("egress_catalog_invalid")
        with self._database(catalog) as database:
            try:
                return self._mandatory(binding, database).inspect(
                    binding.echo_operation_id, binding.echo_binding_digest
                )
            except EchoError as exception:
                raise NativeEgressError(str(exception)) from None

    def ambiguity_challenge(self, binding: OperationBinding) -> dict[str, str]:
        """Return bounded identifiers without projection, request, or secret data."""

        if self._installation_digest is None or self._owner_actor is None:
            raise NativeEgressError("egress_recovery_unavailable")
        catalog = self._catalogs.get(binding.catalog_id)
        if catalog is None:
            raise NativeEgressError("egress_catalog_invalid")
        with self._database(catalog) as database:
            try:
                echo = self._mandatory(binding, database).ambiguity(
                    binding.echo_operation_id, binding.echo_binding_digest
                )
            except EchoError as exception:
                raise NativeEgressError(str(exception)) from None
        return {
            "visibility_installation_sha256": self._installation_digest,
            "policy_sha256": self.policy_digest,
            "catalog_id": binding.catalog_id,
            "path_id": binding.path_id,
            "native_operation_id": binding.operation_id,
            **echo,
        }

    def retry_ambiguous(
        self, binding: OperationBinding, authorization: bytes
    ) -> dict[str, Any]:
        """Owner-only signed recovery under the same fence as normal execution."""

        catalog = self._catalogs.get(binding.catalog_id)
        if catalog is None:
            raise NativeEgressError("egress_catalog_invalid")
        try:
            with self._database(catalog) as database:
                return self._retry_mandatory(binding, database).retry_ambiguous(
                    binding.echo_operation_id,
                    binding.echo_binding_digest,
                    authorization,
                )
        except NativeEgressError:
            raise
        except EchoError as exception:
            if str(exception).startswith("echo_retry"):
                raise NativeEgressError("egress_retry_unauthorized") from None
            raise NativeEgressError(str(exception)) from None

    def advance_one(self, binding: OperationBinding) -> dict[str, Any]:
        catalog = self._catalogs.get(binding.catalog_id)
        if catalog is None:
            raise NativeEgressError("egress_catalog_invalid")
        with self._fence, self._database(catalog) as database:
            try:
                return self._mandatory(binding, database).advance(
                    binding.echo_operation_id, binding.echo_binding_digest
                )
            except EchoError as exception:
                raise NativeEgressError(str(exception)) from None

    def _issue_permit_locked(
        self, binding: OperationBinding, native_bytes: bytes
    ) -> ReleasePermit:
        catalog = self._catalogs.get(binding.catalog_id)
        if catalog is None or binding.path_id not in PEER_EGRESS_PATHS:
            raise NativeEgressError("egress_operation_invalid")
        if _digest(native_bytes) != binding.native_sha256:
            raise NativeEgressError("egress_operation_mismatch")
        if not self._authorize(binding, catalog):
            raise NativeEgressError("egress_authority_blocked")
        if binding.path_id in INTRA_BEING_LANE_PATHS:
            nonce = str(uuid.uuid4())
            self._live_permits.add(nonce)
            return ReleasePermit(binding, nonce, self._permit_marker)
        with self._database(catalog) as database:
            try:
                echo = self._mandatory(binding, database)
                state = echo.inspect(
                    binding.echo_operation_id, binding.echo_binding_digest
                )
                for _ in range(len(state.get("parts", [])) + 1):
                    if state.get("state") in {"confirmed", "ambiguous"}:
                        break
                    state = echo.advance(
                        binding.echo_operation_id, binding.echo_binding_digest
                    )
                echo.require_confirmed(
                    binding.echo_operation_id, binding.echo_binding_digest
                )
            except EchoError as exception:
                if str(exception) == "echo_not_confirmed":
                    raise NativeEgressError("egress_echo_not_confirmed") from None
                raise NativeEgressError(str(exception)) from None
        nonce = str(uuid.uuid4())
        self._live_permits.add(nonce)
        return ReleasePermit(binding, nonce, self._permit_marker)

    def _consume_permit_locked(
        self,
        permit: ReleasePermit,
        native_bytes: bytes,
        effect: Callable[[bytes], _Result],
    ) -> _Result:
        if (
            not isinstance(permit, ReleasePermit)
            or permit._marker is not self._permit_marker
            or permit.nonce not in self._live_permits
        ):
            raise NativeEgressError("egress_permit_invalid")
        self._live_permits.remove(permit.nonce)
        if _digest(native_bytes) != permit.binding.native_sha256:
            raise NativeEgressError("egress_operation_mismatch")
        result = effect(native_bytes)
        catalog = self._catalogs[permit.binding.catalog_id]
        with self._database(catalog) as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE mandatory_egress_operations SET release_count=release_count+1 "
                "WHERE operation_id=?",
                (permit.binding.operation_id,),
            )
            database.commit()
        return result

    def release(
        self,
        binding: OperationBinding,
        native_bytes: bytes,
        effect: Callable[[bytes], _Result],
    ) -> _Result:
        """Issue and consume exactly one permit without releasing the shared fence."""

        with self._fence:
            permit = self._issue_permit_locked(binding, native_bytes)
            return self._consume_permit_locked(permit, native_bytes, effect)

    def release_all(
        self,
        bindings: tuple[OperationBinding, ...],
        native_bytes: bytes,
        effect: Callable[[bytes], _Result],
    ) -> _Result:
        if not bindings:
            raise NativeEgressError("egress_permit_invalid")
        with self._fence:
            permits = [
                self._issue_permit_locked(item, native_bytes) for item in bindings
            ]
            # Every dependency is consumed by this one carrier call.  Consume the
            # first around I/O and invalidate the remaining permits immediately.
            first, *rest = permits
            for permit in rest:
                self._live_permits.remove(permit.nonce)
            return self._consume_permit_locked(first, native_bytes, effect)

    def _queued_bindings(self) -> list[tuple[int, str, str, OperationBinding]]:
        rows: list[tuple[int, str, str, OperationBinding]] = []
        for catalog_id, catalog in self._catalogs.items():
            with self._database(catalog) as database:
                for row in database.execute(
                    "SELECT * FROM mandatory_egress_operations "
                    "ORDER BY created_at_ms, operation_id"
                ):
                    binding = self._binding_from_row(catalog_id, row)
                    rows.append(
                        (
                            int(row["created_at_ms"]),
                            binding.operation_id,
                            catalog_id,
                            binding,
                        )
                    )
        rows.sort(key=lambda item: item[:3])
        return rows

    def run_worker_batch(self, *, limit: int = 32) -> dict[str, int | str | None]:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 128
        ):
            raise NativeEgressError("egress_worker_bounds")
        processed = 0
        for _, _, _, binding in self._queued_bindings():
            if processed >= limit:
                break
            try:
                state = self.inspect(binding)["state"]
            except NativeEgressError:
                continue
            if state != "queued":
                continue
            self.advance_one(binding)
            processed += 1
        return {"processed": processed, **self.status()}

    def status(self) -> dict[str, int | str | None]:
        counts = {"pending": 0, "retryable": 0, "quarantined": 0}
        oldest: int | None = None
        now = self._clock()
        for created, _, _, binding in self._queued_bindings():
            try:
                state = self.inspect(binding)["state"]
            except NativeEgressError:
                counts["quarantined"] += 1
                continue
            if state == "queued":
                counts["pending"] += 1
                age = max(0, now - created)
                oldest = age if oldest is None else max(oldest, age)
            elif state == "ambiguous":
                counts["quarantined"] += 1
        with self._worker_lock:
            worker_state = self._worker_state
            worker_failures = self._worker_failures
        registry_healthy = (
            self._registry_closed
            and self._validated_paths is not None
            and set(self._paths) == set(self._validated_paths)
            and all(
                catalog_id in self._catalogs
                for catalog_ids in self._paths.values()
                for catalog_id in catalog_ids
            )
            and all(self._paths.values())
        )
        return {
            **counts,
            "oldest_pending_age_ms": oldest,
            "worker_state": worker_state,
            "worker_failures": worker_failures,
            "registry_state": "closed" if self._registry_closed else "open",
            "registry_healthy": registry_healthy,
            "registered_catalogs": len(self._catalogs),
            "registered_paths": len(self._paths),
            "registered_bindings": sum(len(value) for value in self._paths.values()),
        }

    def operation_record(self, binding: OperationBinding) -> dict[str, Any]:
        """Bounded diagnostic record; intentionally excludes payload/projection text."""

        return {
            **asdict(binding),
            "native_sha256": binding.native_sha256,
            "projection_sha256": binding.projection_sha256,
        }
