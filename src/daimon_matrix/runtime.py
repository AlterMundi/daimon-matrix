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
from .peer_transport import (
    KeystorePeerCustody,
    PeerClient,
    PeerClientContext,
    PeerDispatcher,
    PeerExchangeStore,
    PeerOutbox,
    http_peer_round_trip,
    protocol_handlers,
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
from .service import SERVICE_METHODS, HostedWeave
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
    if schema in {BUNDLE_SCHEMA_V2, BUNDLE_SCHEMA_V3}:
        fields.add("authority_history")
    if schema == BUNDLE_SCHEMA_V3:
        fields.add("peer_transport")
    bundle = _closed(raw_bundle, fields)
    if schema not in {BUNDLE_SCHEMA, BUNDLE_SCHEMA_V2, BUNDLE_SCHEMA_V3}:
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
        if schema in {BUNDLE_SCHEMA_V2, BUNDLE_SCHEMA_V3}:
            authority_history = bundle["authority_history"]
            if (
                not isinstance(authority_history, list)
                or len(authority_history) > 256
                or (schema == BUNDLE_SCHEMA_V2 and not authority_history)
            ):
                raise RuntimeError("invalid_authority_history")
            historical_authorities = []
            successors = []
            for entry in authority_history:
                epoch = _closed(entry, {"manifest", "successor"})
                historical_authorities.append(
                    RootAuthority(
                        BeingManifest.from_value(epoch["manifest"]),
                        state,
                        credentials,
                        incarnations,
                    )
                )
                successors.append(epoch["successor"])
            if authority_history:
                authority = RootHistoryAuthority(
                    active, historical_authorities, successors
                )
        if history is not None:
            if schema in {BUNDLE_SCHEMA_V2, BUNDLE_SCHEMA_V3}:
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

    custody = _closed(bundle["keystore"], {"counter", "filename", "signing_slot"})
    counter = custody["counter"]
    signing_slot = custody["signing_slot"]
    if (
        not isinstance(counter, int)
        or isinstance(counter, bool)
        or counter < 1
        or not isinstance(signing_slot, str)
        or not signing_slot.startswith("runtime.signing.v1:")
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
    for row in capability_rows:
        value = _closed(row, {"descriptor", "secret_slot"})
        slot = value["secret_slot"]
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
        capabilities[capability.capability_id] = capability

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
    if schema == BUNDLE_SCHEMA_V3 and bundle["peer_transport"] is not None:
        peer_configuration = _closed(
            bundle["peer_transport"],
            {
                "enabled",
                "encryption_slot",
                "exchange_filename",
                "listen_host",
                "listen_port",
                "outbox_filename",
            },
        )
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
    "HostedRuntime",
    "RuntimeError",
    "load_runtime",
]
