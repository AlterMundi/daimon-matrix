"""Fail-closed loader for one public hosted-runtime bundle and secret custody."""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .authority_epochs import RootHistoryAuthority
from .canonical import CanonicalError, canonical_bytes, unb64url
from .client import CLIENT_CONFIG_SCHEMA_V3
from .cluster import FenceVerifier
from .communication import CommunicationStore
from .curator import CuratorCoordinator, EffectTruthObserver
from .identity import (
    ControlChain,
    VerificationError,
    verify_binding_activation,
    verify_embodiment_credential,
    verify_incarnation_authorization,
)
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .ledger import Ledger
from .local_api import LocalCapability
from .operator_capabilities import (
    OPERATOR_PROFILE_NAMES,
    OperatorCapabilityError,
    operator_capability_profile,
    operator_capability_slot,
    operator_runtime_id,
    verify_operator_capability_binding,
)
from .peer_transport import (
    KeystorePeerCustody,
    PeerClient,
    PeerClientContext,
    PeerDispatcher,
    PeerExchangeStore,
    PeerOutbox,
    PeerTransportError,
    http_peer_round_trip,
    protocol_handlers,
)
from .relationship_store import (
    RelationshipServiceContext,
    RelationshipStore,
    RelationshipStoreError,
)
from .relationships import (
    RelationshipError,
    SnapshotVerifier,
    VerifiedTribeSnapshot,
)
from .routes import (
    DirectHTTPProvider,
    HubProvider,
    LocalIPCProvider,
    Provider,
    RouteBinding,
    RouteCoordinator,
    RouteError,
    RouteProfile,
)
from .scopes import BodyReader, ScopeError, ScopeExchangeStore, ScopeResolver
from .sealed import RecipientTarget
from .service import OPERATOR_CAPABILITY_PROFILES, SERVICE_METHODS, HostedWeave
from .sources import SourceCAS, SourceError, SourceRegistry, SourceServiceContext
from .species import SpeciesCAS, SpeciesError, SpeciesRegistry, SpeciesServiceContext
from .sync import SyncEngine
from .weave import (
    BeingManifest,
    BoundHistoryAuthority,
    EventSigner,
    ProvisionalAuthority,
    RootAuthority,
    WeaveProtocolError,
)

BUNDLE_SCHEMA: Final = "dm.runtime.bundle/v1"
BUNDLE_SCHEMA_V2: Final = "dm.runtime.bundle/v2"
BUNDLE_SCHEMA_V3: Final = "dm.runtime.bundle/v3"
BUNDLE_SCHEMA_V4: Final = "dm.runtime.bundle/v4"
BUNDLE_SCHEMA_V5: Final = "dm.runtime.bundle/v5"
BUNDLE_SCHEMA_V6: Final = "dm.runtime.bundle/v6"
BUNDLE_SCHEMA_V7: Final = "dm.runtime.bundle/v7"
MAX_BUNDLE_BYTES: Final = 4 * 1024 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
Clock = Callable[[], int]


class RuntimeError(ValueError):
    """Public authority, paths, or custody cannot safely host a runtime."""


@dataclass(frozen=True)
class HostedRuntime:
    service: HostedWeave
    state_root: Path
    state_identity: tuple[int, int]
    socket_path: Path
    peer_dispatcher: PeerDispatcher | None = None
    peer_outbox: PeerOutbox | None = None
    peer_context: PeerClientContext | None = None
    peer_listen: tuple[str, int] | None = None

    def create_peer_client(
        self, endpoint: str, *, timeout_seconds: float = 10
    ) -> PeerClient:
        if self.peer_context is None:
            raise RuntimeError("peer_transport_not_configured")
        return self.peer_context.client(
            http_peer_round_trip(endpoint, timeout_seconds=timeout_seconds)
        )


def _closed(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeError("invalid_runtime_bundle")
    return value


def _owner_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exception:
        raise RuntimeError("state_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RuntimeError("state_root_not_owner_only")
    ancestor = path.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise RuntimeError("state_root_ancestor_symlink")
        ancestor = ancestor.parent


def _safe_file(root: Path, name: Any, *, must_exist: bool) -> Path:
    if not isinstance(name, str) or _SAFE_NAME.fullmatch(name) is None:
        raise RuntimeError("unsafe_runtime_filename")
    path = root / name
    if must_exist:
        try:
            info = path.lstat()
        except FileNotFoundError as exception:
            raise RuntimeError("runtime_file_missing") from exception
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RuntimeError("runtime_file_not_owner_only")
    return path


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("runtime_bundle_duplicate_key")
        result[key] = value
    return result


def _read_bundle(path: Path) -> Mapping[str, Any]:
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise RuntimeError("runtime_bundle_replaced")
        raw = os.read(descriptor, MAX_BUNDLE_BYTES + 1)
        if not raw or len(raw) > MAX_BUNDLE_BYTES:
            raise RuntimeError("invalid_runtime_bundle_size")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
            raise RuntimeError("runtime_bundle_not_canonical")
        return value
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise RuntimeError("invalid_runtime_bundle") from exception


def _read_private_bytes(path: Path, *, expected_size: int) -> bytes:
    """Read one owner-only regular file through a stable descriptor."""

    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or not stat.S_ISREG(after.st_mode)
                or after.st_uid != os.geteuid()
                or stat.S_IMODE(after.st_mode) & 0o077
                or after.st_size != expected_size
            ):
                raise RuntimeError("runtime_file_not_owner_only")
            raw = os.read(descriptor, expected_size + 1)
        finally:
            os.close(descriptor)
    except OSError as exception:
        raise RuntimeError("runtime_file_not_owner_only") from exception
    if len(raw) != expected_size:
        raise RuntimeError("invalid_runtime_client_key")
    return raw


def _indexed(values: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list) or not 1 <= len(values) <= 256:
        raise RuntimeError("invalid_runtime_bundle")
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(
            value.get("artifact_id"), str
        ):
            raise RuntimeError("invalid_runtime_artifact")
        artifact_id = value["artifact_id"]
        if artifact_id in result:
            raise RuntimeError("duplicate_runtime_artifact")
        result[artifact_id] = copy.deepcopy(dict(value))
    return result


def _event_index(values: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list) or len(values) > 65_536:
        raise RuntimeError("invalid_historical_events")
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or not isinstance(value.get("event_id"), str):
            raise RuntimeError("invalid_historical_event")
        event_id = value["event_id"]
        if event_id in result:
            raise RuntimeError("duplicate_historical_event")
        result[event_id] = copy.deepcopy(dict(value))
    return result


def load_runtime(
    state_root: Path,
    bundle_name: str,
    password_reader: PasswordReader,
    *,
    clock: Clock,
    body_reader: BodyReader | None = None,
    tribe_verifier: SnapshotVerifier | None = None,
    curator_fence_verifier: FenceVerifier | None = None,
    curator_effect_observer: EffectTruthObserver | None = None,
) -> HostedRuntime:
    """Verify all public/secret bindings before exposing a hosted service."""

    root = Path(os.path.abspath(state_root))
    _owner_directory(root)
    root_info = root.lstat()
    bundle_path = _safe_file(root, bundle_name, must_exist=True)
    raw_bundle = _read_bundle(bundle_path)
    if not isinstance(raw_bundle, Mapping):
        raise RuntimeError("invalid_runtime_bundle")
    schema = raw_bundle.get("schema")
    fields = {
        "binding",
        "binding_activation",
        "capabilities",
        "control_artifacts",
        "control_head",
        "credentials",
        "incarnations",
        "keystore",
        "ledger",
        "local_origin",
        "manifest",
        "provisional_history",
        "routing",
        "scopes",
        "schema",
        "socket",
    }
    if schema in {
        BUNDLE_SCHEMA_V2,
        BUNDLE_SCHEMA_V3,
        BUNDLE_SCHEMA_V4,
        BUNDLE_SCHEMA_V5,
        BUNDLE_SCHEMA_V6,
        BUNDLE_SCHEMA_V7,
    }:
        fields.add("authority_history")
    if schema in {
        BUNDLE_SCHEMA_V3,
        BUNDLE_SCHEMA_V4,
        BUNDLE_SCHEMA_V5,
        BUNDLE_SCHEMA_V6,
        BUNDLE_SCHEMA_V7,
    }:
        fields.add("peer_transport")
    if schema in {
        BUNDLE_SCHEMA_V4,
        BUNDLE_SCHEMA_V5,
        BUNDLE_SCHEMA_V6,
        BUNDLE_SCHEMA_V7,
    }:
        fields.add("species")
    if schema in {BUNDLE_SCHEMA_V5, BUNDLE_SCHEMA_V6, BUNDLE_SCHEMA_V7}:
        fields.add("sources")
    if schema in {BUNDLE_SCHEMA_V6, BUNDLE_SCHEMA_V7}:
        fields.add("relationships")
    if schema == BUNDLE_SCHEMA_V7:
        fields.update({"operator_capability_binding", "runtime_id", "runtime_label"})
    bundle = _closed(raw_bundle, fields)
    if schema not in {
        BUNDLE_SCHEMA,
        BUNDLE_SCHEMA_V2,
        BUNDLE_SCHEMA_V3,
        BUNDLE_SCHEMA_V4,
        BUNDLE_SCHEMA_V5,
        BUNDLE_SCHEMA_V6,
        BUNDLE_SCHEMA_V7,
    }:
        raise RuntimeError("unsupported_runtime_bundle")
    controls = bundle["control_artifacts"]
    if not isinstance(controls, list) or not 1 <= len(controls) <= 1024:
        raise RuntimeError("invalid_control_chain")
    try:
        chain = ControlChain(controls[0])
        for artifact in controls[1:]:
            chain.add(artifact)
        state = chain.state
        if bundle["control_head"] != state.head:
            raise RuntimeError("runtime_control_head_mismatch")

        binding = bundle["binding"]
        activation = bundle["binding_activation"]
        history = bundle["provisional_history"]
        if (binding is None) != (activation is None) or (binding is None) != (
            history is None
        ):
            raise RuntimeError("incomplete_history_binding")
        if binding is not None:
            if not isinstance(binding, Mapping) or not isinstance(activation, Mapping):
                raise RuntimeError("invalid_history_binding")
            state = verify_binding_activation(activation, binding, state)

        manifest = BeingManifest.from_value(bundle["manifest"])
        credentials = _indexed(bundle["credentials"])
        incarnations = _indexed(bundle["incarnations"])
        active = RootAuthority(manifest, state, credentials, incarnations)
        authority: RootAuthority | RootHistoryAuthority | BoundHistoryAuthority = active
        if schema in {
            BUNDLE_SCHEMA_V2,
            BUNDLE_SCHEMA_V3,
            BUNDLE_SCHEMA_V4,
            BUNDLE_SCHEMA_V5,
            BUNDLE_SCHEMA_V6,
            BUNDLE_SCHEMA_V7,
        }:
            authority_history = bundle["authority_history"]
            if (
                not isinstance(authority_history, list)
                or len(authority_history) > 256
                or (schema == BUNDLE_SCHEMA_V2 and not authority_history)
            ):
                raise RuntimeError("invalid_authority_history")
            epochs: list[Mapping[str, Any]] = []
            for entry in authority_history:
                if isinstance(entry, Mapping) and set(entry) == {
                    "manifest",
                    "successor",
                }:
                    epochs.append(entry)
                else:
                    if schema != BUNDLE_SCHEMA_V7:
                        raise RuntimeError("invalid_authority_history")
                    epochs.append(
                        _closed(
                            entry,
                            {
                                "manifest",
                                "control_artifacts",
                                "control_head",
                                "credentials",
                                "incarnations",
                                "successor",
                            },
                        )
                    )
            historical_reversed: list[RootAuthority] = []
            next_authority = active
            for epoch in reversed(epochs):
                if set(epoch) == {"manifest", "successor"}:
                    historical_authority = RootAuthority(
                        BeingManifest.from_value(epoch["manifest"]),
                        next_authority.state,
                        next_authority.credentials,
                        next_authority.incarnations,
                    )
                else:
                    historical_controls = epoch["control_artifacts"]
                    if (
                        not isinstance(historical_controls, list)
                        or not 1 <= len(historical_controls) <= 1024
                    ):
                        raise RuntimeError("invalid_authority_history")
                    historical_chain = ControlChain(historical_controls[0])
                    for artifact in historical_controls[1:]:
                        historical_chain.add(artifact)
                    historical_state = historical_chain.state
                    if epoch["control_head"] != historical_state.head:
                        raise RuntimeError("invalid_authority_history")
                    historical_authority = RootAuthority(
                        BeingManifest.from_value(epoch["manifest"]),
                        historical_state,
                        _indexed(epoch["credentials"]),
                        _indexed(epoch["incarnations"]),
                    )
                historical_reversed.append(historical_authority)
                next_authority = historical_authority
            if authority_history:
                historical_authorities = list(reversed(historical_reversed))
                successors = [epoch["successor"] for epoch in epochs]
                authority = RootHistoryAuthority(
                    active, historical_authorities, successors
                )
        if history is not None:
            if schema in {
                BUNDLE_SCHEMA_V2,
                BUNDLE_SCHEMA_V3,
                BUNDLE_SCHEMA_V4,
                BUNDLE_SCHEMA_V5,
                BUNDLE_SCHEMA_V6,
                BUNDLE_SCHEMA_V7,
            }:
                raise RuntimeError("incompatible_authority_histories")
            history_value = _closed(history, {"events", "manifest", "public_keys"})
            public_keys = history_value["public_keys"]
            if not isinstance(public_keys, Mapping):
                raise RuntimeError("invalid_historical_keys")
            historical = ProvisionalAuthority(
                BeingManifest.from_value(history_value["manifest"]),
                public_keys,
            )
            authority = BoundHistoryAuthority(
                active,
                historical,
                binding,
                _event_index(history_value["events"]),
            )
    except (
        AttributeError,
        VerificationError,
        WeaveProtocolError,
        TypeError,
        KeyError,
    ) as exception:
        raise RuntimeError("runtime_authority_rejected") from exception

    local_origin = _closed(
        bundle["local_origin"],
        {"body_ref", "embodiment_id", "incarnation_id", "principal_id"},
    )
    try:
        member = authority.validate_origin(local_origin, require_active=True)
        credential = credentials[member["embodiment_credential_id"]]
        incarnation = incarnations[member["incarnation_authorization_id"]]
        credential_body = verify_embodiment_credential(credential, state, at_ms=clock())
        verify_incarnation_authorization(incarnation, credential, state, at_ms=clock())
    except (KeyError, VerificationError, WeaveProtocolError) as exception:
        raise RuntimeError("local_authorization_not_active") from exception

    runtime_id: str | None = None
    runtime_label: str | None = None
    if schema == BUNDLE_SCHEMA_V7:
        runtime_id = bundle["runtime_id"]
        runtime_label = bundle["runtime_label"]
        try:
            expected_runtime_id = operator_runtime_id(
                runtime_label,
                state.being_ref,
                local_origin,
                credential_body["signing_key"]["key_id"],
            )
        except (KeyError, OperatorCapabilityError, TypeError) as exception:
            raise RuntimeError("invalid_operator_runtime_identity") from exception
        if runtime_id != expected_runtime_id:
            raise RuntimeError("invalid_operator_runtime_identity")
        try:
            verify_operator_capability_binding(
                bundle["operator_capability_binding"],
                runtime_id=runtime_id,
                runtime_label=runtime_label,
                being_ref=state.being_ref,
                origin=local_origin,
                signing_key=credential_body["signing_key"],
                capability_rows=bundle["capabilities"],
            )
        except (KeyError, OperatorCapabilityError, TypeError) as exception:
            raise RuntimeError("invalid_operator_capability_binding") from exception

    custody = _closed(bundle["keystore"], {"counter", "filename", "signing_slot"})
    counter = custody["counter"]
    signing_slot = custody["signing_slot"]
    if (
        not isinstance(counter, int)
        or isinstance(counter, bool)
        or counter < 1
        or not isinstance(signing_slot, str)
        or not signing_slot.startswith("runtime.signing.v1:")
        or (
            schema == BUNDLE_SCHEMA_V7
            and signing_slot != f"runtime.signing.v1:{runtime_label}"
        )
    ):
        raise RuntimeError("invalid_runtime_custody")
    keystore_path = _safe_file(root, custody["filename"], must_exist=True)
    ledger_path = _safe_file(root, bundle["ledger"], must_exist=False)
    socket_path = _safe_file(root, bundle["socket"], must_exist=False)
    filenames = {
        bundle_path.name,
        keystore_path.name,
        ledger_path.name,
        socket_path.name,
    }
    if len(filenames) != 4:
        raise RuntimeError("runtime_filename_collision")
    try:
        contents = EncryptedKeystore(keystore_path).open(
            password_reader,
            minimum_counter=counter,
            required_control_head=state.head,
        )
    except KeystoreError as exception:
        raise RuntimeError("runtime_custody_rejected") from exception
    capability_rows = bundle["capabilities"]
    if not isinstance(capability_rows, list) or not 1 <= len(capability_rows) <= 64:
        raise RuntimeError("runtime_requires_capability")
    required_slots = {signing_slot}
    capabilities: dict[str, LocalCapability] = {}
    operator_clients: dict[str, tuple[LocalCapability, bytes, Mapping[str, Any]]] = {}
    capabilities_observed_at_ms = clock()
    for row in capability_rows:
        value = _closed(
            row,
            (
                {"descriptor", "profile", "runtime_id", "secret_slot"}
                if schema == BUNDLE_SCHEMA_V7
                else {"descriptor", "secret_slot"}
            ),
        )
        slot = value["secret_slot"]
        if schema == BUNDLE_SCHEMA_V7 and value["runtime_id"] != runtime_id:
            raise RuntimeError("invalid_operator_runtime_identity")
        if not isinstance(slot, str) or not slot.startswith("runtime.capability.v1:"):
            raise RuntimeError("invalid_capability_slot")
        if slot in required_slots:
            raise RuntimeError("duplicate_runtime_slot")
        required_slots.add(slot)
        key = contents.secrets.get(slot)
        if key is None:
            raise RuntimeError("missing_runtime_secret")
        capability = LocalCapability.from_value(value["descriptor"], key)
        if (
            not set(capability.methods) <= SERVICE_METHODS
            or capability.capability_id in capabilities
        ):
            raise RuntimeError("invalid_runtime_capability")
        if (
            capability.descriptor["status"] != "active"
            or not capability.descriptor["not_before_ms"]
            <= capabilities_observed_at_ms
            < capability.descriptor["not_after_ms"]
        ):
            raise RuntimeError("runtime_capability_not_active")
        if schema == BUNDLE_SCHEMA_V7:
            profile_value = value["profile"]
            if not isinstance(profile_value, Mapping):
                raise RuntimeError("invalid_operator_capability_profile")
            role = profile_value.get("role")
            if not isinstance(role, str) or role not in OPERATOR_CAPABILITY_PROFILES:
                raise RuntimeError("invalid_operator_capability_profile")
            try:
                expected_profile = operator_capability_profile(role)
                if capability.client_id != f"client:operator:{runtime_label}:{role}":
                    raise OperatorCapabilityError(
                        "invalid_operator_capability_identity"
                    )
                assert runtime_label is not None
                expected_slot = operator_capability_slot(runtime_label, role)
            except OperatorCapabilityError as exception:
                raise RuntimeError("invalid_operator_capability_profile") from exception
            if (
                dict(profile_value) != expected_profile
                or slot != expected_slot
                or frozenset(capability.methods) != OPERATOR_CAPABILITY_PROFILES[role]
                or role in operator_clients
            ):
                raise RuntimeError("invalid_operator_capability_profile")
            operator_clients[role] = (capability, key, profile_value)
        capabilities[capability.capability_id] = capability

    if schema == BUNDLE_SCHEMA_V7:
        if set(operator_clients) != set(OPERATOR_PROFILE_NAMES) or len(
            {capability.key_id for capability, _, _ in operator_clients.values()}
        ) != len(OPERATOR_PROFILE_NAMES):
            raise RuntimeError("invalid_operator_capability_profile")
        for role in OPERATOR_PROFILE_NAMES:
            capability, key, profile_value = operator_clients[role]
            if profile_value["client_directory"] == ".":
                client_root = root
            else:
                clients_root = root / "operator-clients"
                _owner_directory(clients_root)
                client_root = clients_root / role
                _owner_directory(client_root)
            config_path = _safe_file(
                client_root,
                profile_value["client_config_filename"],
                must_exist=True,
            )
            key_path = _safe_file(
                client_root,
                profile_value["client_key_filename"],
                must_exist=True,
            )
            config = _closed(
                _read_bundle(config_path),
                {
                    "capability",
                    "expected_server",
                    "runtime_id",
                    "runtime_label",
                    "schema",
                },
            )
            if (
                config["schema"] != CLIENT_CONFIG_SCHEMA_V3
                or config["capability"] != capability.descriptor
                or config["expected_server"] != local_origin
                or config["runtime_id"] != runtime_id
                or config["runtime_label"] != runtime_label
                or _read_private_bytes(key_path, expected_size=32) != key
            ):
                raise RuntimeError("runtime_operator_client_mismatch")

    route_profile: RouteProfile | None = None
    route_rows: list[tuple[RouteBinding, Mapping[str, Any], bytes]] = []
    routing = bundle["routing"]
    if routing is not None:
        route_bundle = _closed(routing, {"filename", "profile"})
        try:
            route_profile = RouteProfile.from_value(route_bundle["profile"])
        except RouteError as exception:
            raise RuntimeError("runtime_route_profile_rejected") from exception
        if (
            route_profile.body_ref != local_origin["body_ref"]
            or route_profile.principal_id != local_origin["principal_id"]
        ):
            raise RuntimeError("runtime_route_profile_origin_mismatch")
        route_path = _safe_file(root, route_bundle["filename"], must_exist=True)
        if route_path.name in filenames:
            raise RuntimeError("runtime_filename_collision")
        filenames.add(route_path.name)
        private = _closed(_read_bundle(route_path), {"providers", "schema"})
        if private["schema"] != "dm.route-custody/v1":
            raise RuntimeError("unsupported_route_custody")
        provider_rows = private["providers"]
        if not isinstance(provider_rows, list) or len(provider_rows) > 256:
            raise RuntimeError("invalid_route_custody")
        seen_providers: set[str] = set()
        for raw_provider in provider_rows:
            provider = _closed(
                raw_provider,
                {
                    "endpoint",
                    "key_ref",
                    "kind",
                    "provider_ref",
                    "route_ref",
                    "secret_slot",
                    "timeout_ms",
                },
            )
            provider_ref = provider["provider_ref"]
            route_ref = provider["route_ref"]
            key_ref = provider["key_ref"]
            kind = provider["kind"]
            endpoint = provider["endpoint"]
            slot = provider["secret_slot"]
            timeout_ms = provider["timeout_ms"]
            if (
                not all(
                    isinstance(value, str) and value
                    for value in (provider_ref, route_ref, key_ref, endpoint, slot)
                )
                or kind not in {"local", "direct", "hub"}
                or not isinstance(timeout_ms, int)
                or isinstance(timeout_ms, bool)
                or not 1 <= timeout_ms <= 30_000
                or not slot.startswith("runtime.route.v1:")
                or provider_ref in seen_providers
                or slot in required_slots
            ):
                raise RuntimeError("invalid_route_custody")
            bindings = [
                binding
                for binding in route_profile.routes
                if binding.provider_ref == provider_ref
                and binding.route_ref == route_ref
            ]
            if not bindings or len({binding.route_class for binding in bindings}) != 1:
                raise RuntimeError("runtime_route_binding_missing")
            binding = bindings[0]
            if (
                binding.credential_ref != key_ref
                or (kind == "local" and binding.route_class != "local")
                or (
                    kind == "direct"
                    and binding.route_class not in {"direct", "direct-anyvpn"}
                )
                or (kind == "hub" and binding.route_class != "hub")
            ):
                raise RuntimeError("runtime_route_binding_mismatch")
            secret = contents.secrets.get(slot)
            if secret is None or len(secret) != 32:
                raise RuntimeError("missing_runtime_secret")
            required_slots.add(slot)
            seen_providers.add(provider_ref)
            route_rows.append((binding, provider, secret))
        if seen_providers != {
            binding.provider_ref for binding in route_profile.routes if binding.enabled
        }:
            raise RuntimeError("runtime_route_provider_missing")
    peer_configuration: Mapping[str, Any] | None = None
    if (
        schema
        in {
            BUNDLE_SCHEMA_V3,
            BUNDLE_SCHEMA_V4,
            BUNDLE_SCHEMA_V5,
            BUNDLE_SCHEMA_V6,
            BUNDLE_SCHEMA_V7,
        }
        and bundle["peer_transport"] is not None
    ):
        peer_fields = {
            "enabled",
            "encryption_slot",
            "exchange_filename",
            "listen_host",
            "listen_port",
            "outbox_filename",
        }
        if schema == BUNDLE_SCHEMA_V7:
            peer_fields.add("targets")
        peer_configuration = _closed(bundle["peer_transport"], peer_fields)
        peer_slot = peer_configuration["encryption_slot"]
        listen_host = peer_configuration["listen_host"]
        listen_port = peer_configuration["listen_port"]
        if (
            peer_configuration["enabled"] is not True
            or not isinstance(peer_slot, str)
            or not peer_slot.startswith("peer.encryption.v1:")
            or peer_slot in required_slots
            or not isinstance(listen_host, str)
            or not 1 <= len(listen_host.encode("utf-8")) <= 255
            or any(character.isspace() for character in listen_host)
            or not isinstance(listen_port, int)
            or isinstance(listen_port, bool)
            or not 1 <= listen_port <= 65_535
        ):
            raise RuntimeError("invalid_peer_transport_configuration")
        if (
            contents.secrets.get(peer_slot) is None
            or len(contents.secrets[peer_slot]) != 32
        ):
            raise RuntimeError("missing_runtime_secret")
        peer_files = [
            _safe_file(root, peer_configuration[field], must_exist=False)
            for field in ("exchange_filename", "outbox_filename")
        ]
        if (
            any(path.name in filenames for path in peer_files)
            or len({path.name for path in peer_files}) != 2
        ):
            raise RuntimeError("runtime_filename_collision")
        filenames.update(path.name for path in peer_files)
        required_slots.add(peer_slot)
    peer_endpoints: dict[str, tuple[str, float]] = {}
    if peer_configuration is not None and schema == BUNDLE_SCHEMA_V7:
        raw_targets = peer_configuration["targets"]
        if not isinstance(raw_targets, list) or len(raw_targets) > 255:
            raise RuntimeError("invalid_peer_target_configuration")
        normalized_targets: list[tuple[str, str, int]] = []
        for raw_target in raw_targets:
            target = _closed(raw_target, {"embodiment_id", "endpoint", "timeout_ms"})
            embodiment_id = target["embodiment_id"]
            endpoint = target["endpoint"]
            timeout_ms = target["timeout_ms"]
            if (
                not isinstance(embodiment_id, str)
                or not isinstance(endpoint, str)
                or not isinstance(timeout_ms, int)
                or isinstance(timeout_ms, bool)
                or not 1 <= timeout_ms <= 30_000
            ):
                raise RuntimeError("invalid_peer_target_configuration")
            try:
                http_peer_round_trip(endpoint, timeout_seconds=timeout_ms / 1000)
            except (PeerTransportError, TypeError, ValueError) as exception:
                raise RuntimeError("invalid_peer_target_configuration") from exception
            normalized_targets.append((embodiment_id, endpoint, timeout_ms))
        if normalized_targets != sorted(normalized_targets) or len(
            {row[0] for row in normalized_targets}
        ) != len(normalized_targets):
            raise RuntimeError("invalid_peer_target_configuration")
        active_remote_ids = {
            str(row["embodiment_id"])
            for row in active.manifest.value["embodiments"]
            if row["status"] == "active"
            and row["embodiment_id"] != local_origin["embodiment_id"]
        }
        if {row[0] for row in normalized_targets} != active_remote_ids:
            raise RuntimeError("invalid_peer_target_configuration")
        peer_endpoints = {
            embodiment_id: (endpoint, timeout_ms / 1000)
            for embodiment_id, endpoint, timeout_ms in normalized_targets
        }
    body_capabilities: tuple[str, ...] = ()
    tribes: dict[str, VerifiedTribeSnapshot] = {}
    scopes_bundle = bundle["scopes"]
    if scopes_bundle is not None:
        scope_value = _closed(
            scopes_bundle, {"body_capabilities", "relationships_filename"}
        )
        capabilities_value = scope_value["body_capabilities"]
        if (
            not isinstance(capabilities_value, list)
            or len(capabilities_value) > 256
            or capabilities_value != sorted(set(capabilities_value))
            or not all(
                isinstance(item, str) and 1 <= len(item.encode()) <= 128
                for item in capabilities_value
            )
        ):
            raise RuntimeError("invalid_scope_configuration")
        body_capabilities = tuple(capabilities_value)
        relationship_name = scope_value["relationships_filename"]
        if relationship_name is not None:
            if tribe_verifier is None:
                raise RuntimeError("runtime_tribe_verifier_required")
            relationship_path = _safe_file(root, relationship_name, must_exist=True)
            if relationship_path.name in filenames:
                raise RuntimeError("runtime_filename_collision")
            filenames.add(relationship_path.name)
            relationship_set = _closed(
                _read_bundle(relationship_path), {"schema", "snapshots"}
            )
            snapshots = relationship_set["snapshots"]
            if (
                relationship_set["schema"] != "dm.tribe-snapshot-set/v1"
                or not isinstance(snapshots, list)
                or len(snapshots) > 256
            ):
                raise RuntimeError("invalid_tribe_snapshot_set")
            try:
                for raw_snapshot in snapshots:
                    snapshot = VerifiedTribeSnapshot.from_value(
                        raw_snapshot, verifier=tribe_verifier
                    )
                    if snapshot.ref in tribes:
                        raise RuntimeError("duplicate_tribe_snapshot")
                    tribes[snapshot.ref] = snapshot
            except RelationshipError as exception:
                raise RuntimeError("runtime_tribe_snapshot_rejected") from exception
    species_context: SpeciesServiceContext | None = None
    if (
        schema
        in {
            BUNDLE_SCHEMA_V4,
            BUNDLE_SCHEMA_V5,
            BUNDLE_SCHEMA_V6,
            BUNDLE_SCHEMA_V7,
        }
        and bundle["species"] is not None
    ):
        species_value = _closed(
            bundle["species"],
            {
                "cas_filename",
                "enrollment_release_id",
                "local_policy_ref",
                "pointer_filename",
                "registry_filename",
                "species_id",
            },
        )
        species_files = [
            _safe_file(root, species_value[field], must_exist=False)
            for field in ("cas_filename", "pointer_filename", "registry_filename")
        ]
        if any(path.name in filenames for path in species_files) or len(
            {path.name for path in species_files}
        ) != len(species_files):
            raise RuntimeError("runtime_filename_collision")
        filenames.update(path.name for path in species_files)
        try:
            species_cas = SpeciesCAS(species_files[0])
            species_context = SpeciesServiceContext(
                registry=SpeciesRegistry(species_files[2], species_cas),
                species_id=species_value["species_id"],
                enrollment_release_id=species_value["enrollment_release_id"],
                local_policy_ref=species_value["local_policy_ref"],
                pointer_path=species_files[1],
            )
            species_context.registry.initialize()
            species_context.registry.load_local_policy(species_context.local_policy_ref)
        except (KeyError, SpeciesError, TypeError) as exception:
            raise RuntimeError("runtime_species_configuration_rejected") from exception
    relationship_store_path: Path | None = None
    relationship_known_refs: tuple[str, ...] = ()
    if (
        schema in {BUNDLE_SCHEMA_V6, BUNDLE_SCHEMA_V7}
        and bundle["relationships"] is not None
    ):
        relationship_value = _closed(
            bundle["relationships"], {"known_being_refs", "store_filename"}
        )
        relationship_store_path = _safe_file(
            root, relationship_value["store_filename"], must_exist=False
        )
        if relationship_store_path.name in filenames:
            raise RuntimeError("runtime_filename_collision")
        filenames.add(relationship_store_path.name)
        raw_refs = relationship_value["known_being_refs"]
        if (
            not isinstance(raw_refs, list)
            or len(raw_refs) > 256
            or raw_refs != sorted(set(raw_refs))
            or not all(
                isinstance(item, str) and item.startswith("dm:being:v1:")
                for item in raw_refs
            )
        ):
            raise RuntimeError("runtime_relationship_configuration_rejected")
        relationship_known_refs = tuple(raw_refs)
    source_cas_path: Path | None = None
    known_source_configurations: list[tuple[str, Path, Any, Mapping[str, str]]] = []
    if (
        schema in {BUNDLE_SCHEMA_V5, BUNDLE_SCHEMA_V6, BUNDLE_SCHEMA_V7}
        and bundle["sources"] is not None
    ):
        source_value = _closed(bundle["sources"], {"cas_filename", "known_beings"})
        source_cas_path = _safe_file(
            root, source_value["cas_filename"], must_exist=False
        )
        if source_cas_path.name in filenames:
            raise RuntimeError("runtime_filename_collision")
        filenames.add(source_cas_path.name)
        known_beings = source_value["known_beings"]
        if not isinstance(known_beings, list) or len(known_beings) > 256:
            raise RuntimeError("runtime_source_configuration_rejected")
        seen_known_beings: set[str] = set()
        try:
            for raw_known in known_beings:
                known = _closed(
                    raw_known,
                    {
                        "authority_history",
                        "control_artifacts",
                        "control_head",
                        "credentials",
                        "incarnations",
                        "ledger_filename",
                        "manifest",
                    },
                )
                known_controls = known["control_artifacts"]
                if (
                    not isinstance(known_controls, list)
                    or not 1 <= len(known_controls) <= 1024
                ):
                    raise RuntimeError("runtime_source_configuration_rejected")
                known_chain = ControlChain(known_controls[0])
                for artifact in known_controls[1:]:
                    known_chain.add(artifact)
                known_state = known_chain.state
                if known["control_head"] != known_state.head:
                    raise RuntimeError("runtime_source_control_head_mismatch")
                known_manifest = BeingManifest.from_value(known["manifest"])
                known_credentials = _indexed(known["credentials"])
                known_incarnations = _indexed(known["incarnations"])
                known_active = RootAuthority(
                    known_manifest,
                    known_state,
                    known_credentials,
                    known_incarnations,
                )
                known_authority: RootAuthority | RootHistoryAuthority = known_active
                known_history = known["authority_history"]
                if not isinstance(known_history, list) or len(known_history) > 256:
                    raise RuntimeError("runtime_source_configuration_rejected")
                known_epochs: list[Mapping[str, Any]] = []
                for raw_epoch in known_history:
                    if isinstance(raw_epoch, Mapping) and set(raw_epoch) == {
                        "manifest",
                        "successor",
                    }:
                        known_epochs.append(raw_epoch)
                    else:
                        if schema != BUNDLE_SCHEMA_V7:
                            raise RuntimeError("runtime_source_configuration_rejected")
                        known_epochs.append(
                            _closed(
                                raw_epoch,
                                {
                                    "manifest",
                                    "control_artifacts",
                                    "control_head",
                                    "credentials",
                                    "incarnations",
                                    "successor",
                                },
                            )
                        )
                known_historical_reversed: list[RootAuthority] = []
                next_known_authority = known_active
                for epoch in reversed(known_epochs):
                    if set(epoch) == {"manifest", "successor"}:
                        historical_authority = RootAuthority(
                            BeingManifest.from_value(epoch["manifest"]),
                            next_known_authority.state,
                            next_known_authority.credentials,
                            next_known_authority.incarnations,
                        )
                    else:
                        historical_controls = epoch["control_artifacts"]
                        if (
                            not isinstance(historical_controls, list)
                            or not 1 <= len(historical_controls) <= 1024
                        ):
                            raise RuntimeError("runtime_source_configuration_rejected")
                        historical_chain = ControlChain(historical_controls[0])
                        for artifact in historical_controls[1:]:
                            historical_chain.add(artifact)
                        historical_state = historical_chain.state
                        if epoch["control_head"] != historical_state.head:
                            raise RuntimeError("runtime_source_configuration_rejected")
                        historical_authority = RootAuthority(
                            BeingManifest.from_value(epoch["manifest"]),
                            historical_state,
                            _indexed(epoch["credentials"]),
                            _indexed(epoch["incarnations"]),
                        )
                    known_historical_reversed.append(historical_authority)
                    next_known_authority = historical_authority
                if known_history:
                    historical_authorities = list(reversed(known_historical_reversed))
                    known_successors = [epoch["successor"] for epoch in known_epochs]
                    known_authority = RootHistoryAuthority(
                        known_active, historical_authorities, known_successors
                    )
                known_being_ref = known_manifest.being_ref
                if (
                    known_being_ref == manifest.being_ref
                    or known_being_ref in seen_known_beings
                ):
                    raise RuntimeError("runtime_source_being_conflict")
                seen_known_beings.add(known_being_ref)
                active_members = [
                    row
                    for row in known_manifest.value["embodiments"]
                    if row["status"] == "active"
                ]
                if not active_members:
                    raise RuntimeError("runtime_source_authority_inactive")
                known_member = active_members[0]
                known_credential = known_credentials[
                    known_member["embodiment_credential_id"]
                ]
                principals = known_credential["body"]["transport_principals"]
                if not isinstance(principals, list) or not principals:
                    raise RuntimeError("runtime_source_authority_inactive")
                known_origin = {
                    "body_ref": known_member["body_ref"],
                    "embodiment_id": known_member["embodiment_id"],
                    "incarnation_id": known_member["incarnation_id"],
                    "principal_id": principals[0]["principal_id"],
                }
                known_authority.validate_origin(known_origin, require_active=True)
                known_path = _safe_file(
                    root, known["ledger_filename"], must_exist=False
                )
                if known_path.name in filenames:
                    raise RuntimeError("runtime_filename_collision")
                filenames.add(known_path.name)
                known_source_configurations.append(
                    (
                        known_being_ref,
                        known_path,
                        known_authority,
                        known_origin,
                    )
                )
        except (
            AttributeError,
            KeyError,
            SourceError,
            TypeError,
            VerificationError,
            WeaveProtocolError,
        ) as exception:
            raise RuntimeError("runtime_source_configuration_rejected") from exception
    if set(contents.secrets) != required_slots:
        raise RuntimeError("unexpected_runtime_secret_slot")
    seed = contents.secrets.get(signing_slot)
    if seed is None:
        raise RuntimeError("missing_runtime_secret")
    signer = EventSigner(credential_body["signing_key"]["key_id"], seed)
    if signer.public_key != unb64url(
        credential_body["signing_key"]["public"], length=32
    ):
        raise RuntimeError("runtime_signer_mismatch")

    peer_custody: KeystorePeerCustody | None = None
    if peer_configuration is not None:
        encryption_key_id = credential_body["encryption_key"]["key_id"]
        peer_slot_value = peer_configuration["encryption_slot"]
        assert isinstance(peer_slot_value, str)
        try:
            peer_custody = KeystorePeerCustody(
                secrets=contents.secrets,
                signing_slots={credential_body["signing_key"]["key_id"]: signing_slot},
                encryption_slots={encryption_key_id: peer_slot_value},
            )
        except ValueError as exception:
            raise RuntimeError("runtime_peer_transport_rejected") from exception

    ledger = Ledger(
        ledger_path,
        authority=authority,
        local_origin=local_origin,
        clock=clock,
    )
    source_context: SourceServiceContext | None = None
    if source_cas_path is not None:
        known_ledgers = {
            configuration[0]: Ledger(
                configuration[1],
                authority=configuration[2],
                local_origin=configuration[3],
                clock=clock,
            )
            for configuration in known_source_configurations
        }
        try:
            source_context = SourceServiceContext(
                SourceRegistry(
                    ledger,
                    SourceCAS(source_cas_path),
                    clock=clock,
                    known_ledgers=known_ledgers,
                )
            )
            source_context.registry.initialize()
        except SourceError as exception:
            raise RuntimeError("runtime_source_configuration_rejected") from exception
    relationship_context: RelationshipServiceContext | None = None
    if relationship_store_path is not None:
        known_authorities = {
            configuration[0]: configuration[2]
            for configuration in known_source_configurations
        }
        if not set(relationship_known_refs).issubset(known_authorities):
            raise RuntimeError("runtime_relationship_authority_inventory_mismatch")
        relationship_authorities: dict[str, Any] = {
            manifest.being_ref: authority,
            **{
                being_ref: known_authorities[being_ref]
                for being_ref in relationship_known_refs
            },
        }
        active_authorities: dict[str, RootAuthority] = {manifest.being_ref: active}
        for being_ref in relationship_known_refs:
            known_authority = known_authorities[being_ref]
            active_authorities[being_ref] = (
                known_authority.active
                if isinstance(known_authority, RootHistoryAuthority)
                else known_authority
            )

        def verify_relationship_card(card: Mapping[str, Any], at_ms: int) -> None:
            being_ref = card.get("being_ref")
            card_authority = (
                active_authorities.get(being_ref)
                if isinstance(being_ref, str)
                else None
            )
            if card_authority is None or being_ref != card_authority.manifest.being_ref:
                raise RelationshipError("relationship_card_authority_unknown")
            position = card.get("control_position")
            if (
                not isinstance(position, Mapping)
                or position.get("manifest_hash") != card_authority.manifest.digest
            ):
                raise RelationshipError("relationship_card_control_unverified")
            try:
                member = card_authority.manifest.member(
                    position["embodiment_id"], position["incarnation_id"]
                )
                if member["status"] != "active":
                    raise RelationshipError("relationship_card_control_unverified")
                credential = card_authority.credentials[
                    member["embodiment_credential_id"]
                ]
                body = verify_embodiment_credential(
                    credential, card_authority.state, at_ms=at_ms
                )
            except (
                KeyError,
                TypeError,
                VerificationError,
                WeaveProtocolError,
            ) as exception:
                raise RelationshipError(
                    "relationship_card_control_unverified"
                ) from exception
            if (
                card.get("encryption_key") != body["encryption_key"]
                or "messages" not in body["purposes"]
            ):
                raise RelationshipError("relationship_card_control_unverified")

        try:
            relationship_context = RelationshipServiceContext(
                RelationshipStore(
                    relationship_store_path,
                    authority_resolver=lambda being_ref: relationship_authorities[
                        being_ref
                    ],
                ),
                verify_relationship_card,
            )
            relationship_context.store.initialize()
        except (KeyError, RelationshipError, RelationshipStoreError) as exception:
            raise RuntimeError(
                "runtime_relationship_configuration_rejected"
            ) from exception
    if species_context is not None:
        try:
            species_context.registry.recover_pending_applications(
                species_context.pointer_path,
                find_event=lambda event_id: ledger.event(event_id),
            )
        except SpeciesError as exception:
            raise RuntimeError("runtime_species_recovery_rejected") from exception
    communication = CommunicationStore(ledger, clock=clock)
    router: RouteCoordinator | None = None
    if route_profile is not None:
        providers: dict[str, Provider] = {}
        for binding, provider, secret in route_rows:
            common: dict[str, Any] = {
                "provider_ref": binding.provider_ref,
                "route_ref": binding.route_ref,
                "route_class": binding.route_class,
                "key_ref": binding.credential_ref,
                "secret": secret,
                "sender_principal": route_profile.principal_id,
                "sender_body_ref": route_profile.body_ref,
                "clock": clock,
                "timeout_seconds": provider["timeout_ms"] / 1000,
            }
            try:
                kind = provider["kind"]
                if kind == "local":
                    instance: Provider = LocalIPCProvider(
                        socket_path=_safe_file(
                            root, provider["endpoint"], must_exist=False
                        ),
                        **common,
                    )
                elif kind == "direct":
                    instance = DirectHTTPProvider(
                        endpoint=provider["endpoint"], **common
                    )
                else:
                    instance = HubProvider(endpoint=provider["endpoint"], **common)
            except (RouteError, TypeError, ValueError) as exception:
                raise RuntimeError("runtime_route_provider_rejected") from exception
            providers[binding.provider_ref] = instance
        router = RouteCoordinator(communication, route_profile, providers, clock=clock)
    try:
        scopes = ScopeResolver(
            ledger,
            clock=clock,
            router=router,
            body_capabilities=body_capabilities,
            body_reader=body_reader if scopes_bundle is not None else None,
            tribes=tribes,
            peer_embodiments=frozenset(peer_endpoints),
            tribe_provider=(
                None
                if relationship_context is None
                else lambda tribe_ref, at_ms: relationship_context.store.view(
                    at_ms=at_ms,
                    card_verifier=relationship_context.card_verifier,
                ).snapshot(tribe_ref)
            ),
        )
    except ScopeError as exception:
        raise RuntimeError("runtime_scope_configuration_rejected") from exception
    peer_dispatcher: PeerDispatcher | None = None
    peer_outbox: PeerOutbox | None = None
    peer_context: PeerClientContext | None = None
    peer_listen: tuple[str, int] | None = None
    if peer_configuration is not None:
        assert peer_custody is not None
        scope_exchange = ScopeExchangeStore(ledger)
        scope_exchange.initialize()
        try:
            peer_dispatcher = PeerDispatcher(
                authority=active,
                local_origin=local_origin,
                local_target=RecipientTarget(active, credential["artifact_id"]),
                custody=peer_custody,
                store=PeerExchangeStore(
                    _safe_file(
                        root,
                        peer_configuration["exchange_filename"],
                        must_exist=False,
                    ),
                    clock=clock,
                ),
                handlers=protocol_handlers(
                    resolver=scopes,
                    signer=signer,
                    scope_store=scope_exchange,
                    sync_engine=SyncEngine(ledger),
                ),
                clock=clock,
            )
            peer_outbox = PeerOutbox(
                _safe_file(
                    root,
                    peer_configuration["outbox_filename"],
                    must_exist=False,
                )
            )
            peer_context = PeerClientContext(
                authority=active,
                local_origin=local_origin,
                local_target=RecipientTarget(active, credential["artifact_id"]),
                custody=peer_custody,
                outbox=peer_outbox,
                clock=clock,
                endpoints=peer_endpoints,
            )
        except (OSError, TypeError, ValueError) as exception:
            raise RuntimeError("runtime_peer_transport_rejected") from exception
        listen_host_value = peer_configuration["listen_host"]
        listen_port_value = peer_configuration["listen_port"]
        assert isinstance(listen_host_value, str)
        assert isinstance(listen_port_value, int)
        peer_listen = (listen_host_value, listen_port_value)
    service = HostedWeave(
        ledger,
        signer,
        capabilities,
        clock,
        communication=communication,
        router=router,
        scopes=scopes,
        curator=CuratorCoordinator(
            ledger,
            clock,
            fence_verifier=curator_fence_verifier,
            effect_observer=curator_effect_observer,
        ),
        species=species_context,
        sources=source_context,
        relationships=relationship_context,
        peer_context=peer_context,
    )
    ledger.integrity_check()
    final_root = root.lstat()
    identity = (root_info.st_dev, root_info.st_ino)
    if (final_root.st_dev, final_root.st_ino) != identity:
        raise RuntimeError("state_root_replaced")
    return HostedRuntime(
        service,
        root,
        identity,
        socket_path,
        peer_dispatcher=peer_dispatcher,
        peer_outbox=peer_outbox,
        peer_context=peer_context,
        peer_listen=peer_listen,
    )


__all__ = [
    "BUNDLE_SCHEMA",
    "BUNDLE_SCHEMA_V2",
    "BUNDLE_SCHEMA_V3",
    "BUNDLE_SCHEMA_V4",
    "BUNDLE_SCHEMA_V5",
    "BUNDLE_SCHEMA_V6",
    "BUNDLE_SCHEMA_V7",
    "HostedRuntime",
    "RuntimeError",
    "load_runtime",
]
