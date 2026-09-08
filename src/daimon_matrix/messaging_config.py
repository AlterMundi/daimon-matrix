"""Signed owner-local messaging applications; not a model authorization API.

Enrollment is a trusted operator operation, separate from v7 runtime bundles.
No ordinary operator/host capability profiles or runtime schemas are extended.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authority_epochs import RootHistoryAuthority
from .canonical import b64url, canonical_bytes, unb64url
from .identity import verify_embodiment_credential, verify_incarnation_authorization
from .runtime import HostedRuntime
from .weave import RootAuthority

APPLICATION_SCHEMA = "dm.messaging.application/v1"
BINDING_SCHEMA = "dm.messaging.operator-binding/v1"
BINDING_DOMAIN = b"daimon/messaging-operator-binding/v1\x00"


class MessagingConfigError(ValueError):
    """Bounded public error; never includes input values or secret bytes."""


def _identity(runtime: HostedRuntime) -> dict[str, Any]:
    service = runtime.service
    authority = service.ledger.authority
    if not isinstance(authority, (RootAuthority, RootHistoryAuthority)):
        raise MessagingConfigError("messaging_binding_rejected")
    member = authority.validate_origin(service.origin, require_active=True)
    credential = authority.credentials[member["embodiment_credential_id"]]
    incarnation = authority.incarnations[member["incarnation_authorization_id"]]
    verify_embodiment_credential(credential, authority.state, at_ms=service.clock())
    verify_incarnation_authorization(
        incarnation, credential, authority.state, at_ms=service.clock()
    )
    signing = credential["body"]["signing_key"]
    if signing["key_id"] != service.signer.key_id or signing["public"] != b64url(
        service.signer.public_key
    ):
        raise MessagingConfigError("messaging_binding_rejected")
    return {
        "runtime_id": service.runtime_id,
        "runtime_label": service.runtime_label,
        "being_ref": authority.manifest.being_ref,
        "origin": dict(service.origin),
        "control_head": authority.state.head,
        "manifest_hash": authority.manifest.digest,
        "credential_id": member["embodiment_credential_id"],
        "incarnation_authorization_id": member["incarnation_authorization_id"],
        "signing_key_id": signing["key_id"],
    }


def config_digest(application: Any) -> str:
    return hashlib.sha256(canonical_bytes(application)).hexdigest()


def create_binding(runtime: HostedRuntime, application: Any) -> dict[str, Any]:
    """Trusted operator only: purpose-pinned signature via already loaded custody."""
    try:
        if runtime.peer_context is None:
            raise ValueError()
        body = {**_identity(runtime), "application_sha256": config_digest(application)}
        signature = runtime.peer_context.custody.sign(
            body["signing_key_id"], BINDING_DOMAIN + canonical_bytes(body)
        )
        return {"schema": BINDING_SCHEMA, "body": body, "signature": b64url(signature)}
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


def verify_binding(runtime: HostedRuntime, application: Any, binding: Any) -> None:
    try:
        if (
            not isinstance(binding, dict)
            or set(binding) != {"schema", "body", "signature"}
            or binding["schema"] != BINDING_SCHEMA
        ):
            raise ValueError()
        expected = {
            **_identity(runtime),
            "application_sha256": config_digest(application),
        }
        if binding["body"] != expected:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(runtime.service.signer.public_key).verify(
            unb64url(binding["signature"], length=64),
            BINDING_DOMAIN + canonical_bytes(expected),
        )
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


# Kept in Python too: wheels do not ship the repository's public schemas.
def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


_TEXT = {"type": "string", "minLength": 1, "maxLength": 256}
_LEAF = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$"}
_HASH = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
_ROUTE = _object(
    {
        **{k: _TEXT for k in ("provider_ref", "route_ref", "key_ref", "endpoint")},
        "secret_file": _LEAF,
        "secret_sha256": _HASH,
    }
)
_POLICY = _object(
    {
        **{
            k: _TEXT
            for k in (
                "peer_being_ref",
                "peer_embodiment_id",
                "peer_credential_id",
                "relationship_id",
                "tribe_ref",
                "membership_ref",
                "resource_ref",
            )
        },
        "operation": {"const": "read"},
        "classification": {"enum": ["private", "shareable", "public"]},
        "max_ttl_ms": {"type": "integer", "minimum": 1, "maximum": 60000},
        "grant_refs": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "items": _object(
                {k: _TEXT for k in ("grant_id", "event_id", "event_hash")}
            ),
        },
    }
)
_DIRECTION = _object(
    {
        "channel_id": _LEAF,
        "recipient_being_ref": _TEXT,
        "recipient_credential_id": _TEXT,
        "policy": _POLICY,
        "routes": _object({"evidence": _ROUTE, "message": _ROUTE}),
    }
)
STORE_NAMES = (
    "relationships",
    "inbox",
    "outgoing-context",
    "outbox",
    "opaque-evidence",
    "opaque-message",
)
SPECIFICATION_SCHEMA = _object(
    {
        "schema": {"const": APPLICATION_SCHEMA},
        "listen": _object(
            {"host": _TEXT, "port": {"type": "integer", "minimum": 1, "maximum": 65535}}
        ),
        "authorities": {
            "type": "array",
            "minItems": 2,
            "maxItems": 64,
            "items": {"type": "object"},
        },
        "relationship_events": {
            "type": "array",
            "minItems": 1,
            "maxItems": 4096,
            "items": {"type": "object"},
        },
        "incoming": _DIRECTION,
        "outgoing": _DIRECTION,
        "stores": _object({name: _LEAF for name in STORE_NAMES}),
    }
)
APPLICATION_JSON_SCHEMA = _object(
    {
        **SPECIFICATION_SCHEMA["properties"],
        "client": _object(
            {
                "descriptor": {"type": "object"},
                "secret_file": _LEAF,
                "secret_sha256": _HASH,
            }
        ),
    }
)


BINDING_JSON_SCHEMA = _object(
    {
        "schema": {"const": BINDING_SCHEMA},
        "body": _object(
            {
                **{
                    name: _TEXT
                    for name in (
                        "runtime_id",
                        "runtime_label",
                        "being_ref",
                        "control_head",
                        "manifest_hash",
                        "credential_id",
                        "incarnation_authorization_id",
                        "signing_key_id",
                    )
                },
                "origin": _object(
                    {
                        name: _TEXT
                        for name in (
                            "body_ref",
                            "embodiment_id",
                            "incarnation_id",
                            "principal_id",
                        )
                    }
                ),
                "application_sha256": _HASH,
            }
        ),
        "signature": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
    }
)
for _name, _schema in (
    ("application", APPLICATION_JSON_SCHEMA),
    ("operator-binding", BINDING_JSON_SCHEMA),
):
    _schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    _schema["$id"] = f"https://daimon.network/schemas/messaging/v1/{_name}.schema.json"


def _shape(value: Any, schema: dict[str, Any]) -> None:
    import re

    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError()
        if "properties" in schema:
            if set(value) != set(schema["properties"]):
                raise ValueError()
            for name, child in schema["properties"].items():
                _shape(value[name], child)
    elif kind == "array":
        if (
            not isinstance(value, list)
            or not schema["minItems"] <= len(value) <= schema["maxItems"]
        ):
            raise ValueError()
        for item in value:
            _shape(item, schema["items"])
    elif kind == "string":
        if not isinstance(value, str) or not schema.get("minLength", 1) <= len(
            value
        ) <= schema.get("maxLength", 256):
            raise ValueError()
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ValueError()
    elif kind == "integer":
        if (
            type(value) is not int
            or not schema["minimum"] <= value <= schema["maximum"]
        ):
            raise ValueError()
    if "const" in schema and value != schema["const"]:
        raise ValueError()
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError()


def validate_shape(application: Any, *, specification: bool = False) -> None:
    try:
        _shape(
            application,
            SPECIFICATION_SCHEMA if specification else APPLICATION_JSON_SCHEMA,
        )
        # Numeric addresses only: no resolver changes to listener binding.
        import ipaddress
        from urllib.parse import urlsplit

        ipaddress.IPv4Address(application["listen"]["host"])
        if (
            application["incoming"]["channel_id"]
            == application["outgoing"]["channel_id"]
        ):
            raise ValueError()
        for direction in ("incoming", "outgoing"):
            for phase, route in application[direction]["routes"].items():
                endpoint = urlsplit(route["endpoint"])
                if (
                    endpoint.scheme not in {"http", "https"}
                    or not endpoint.hostname
                    or endpoint.username is not None
                    or endpoint.password is not None
                    or endpoint.query
                    or endpoint.fragment
                    or endpoint.port is None
                    or endpoint.path != f"/dm-messaging/v1/{phase}"
                ):
                    raise ValueError()
                if direction == "incoming" and (
                    endpoint.scheme != "http"
                    or endpoint.hostname != application["listen"]["host"]
                    or endpoint.port != application["listen"]["port"]
                ):
                    raise ValueError()
        names = [
            "application.json",
            "binding.json",
            "client.json",
            "client.key",
            "publication.json",
        ]
        names += list(application["stores"].values())
        names += [
            route["secret_file"]
            for d in ("incoming", "outgoing")
            for route in application[d]["routes"].values()
        ]
        if not specification and application["client"]["secret_file"] != "client.key":
            raise ValueError()
        expanded = names + [
            n + suffix
            for n in application["stores"].values()
            for suffix in ("-wal", "-shm", "-journal")
        ]
        if len(set(expanded)) != len(expanded):
            raise ValueError()
    except Exception:
        raise MessagingConfigError("messaging_application_rejected") from None


def _directory(path: Path | str) -> Path:
    """Reject symlink ancestors; trust only owner paths and root sticky ancestors."""
    import os
    import stat
    from pathlib import Path

    path = Path(os.path.abspath(path))
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        st = current.lstat()
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid not in {0, os.geteuid()}
            or (
                st.st_mode & 0o022
                and not (st.st_uid == 0 and st.st_mode & stat.S_ISVTX)
            )
        ):
            raise MessagingConfigError("messaging_directory_rejected")
    st = path.lstat()
    if st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise MessagingConfigError("messaging_directory_rejected")
    return path


def protected_read(path: Path | str, *, size: int | None = None) -> bytes:
    """Bounded, no-follow, owner-only, single-link regular descriptor read."""
    import os
    import stat
    from pathlib import Path

    path = Path(path)
    try:
        _directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or st.st_mode & 0o077
                or st.st_nlink != 1
                or not 0 < st.st_size <= 4 * 1024 * 1024
                or (size is not None and st.st_size != size)
            ):
                raise ValueError()
            chunks = []
            remaining = st.st_size
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    raise ValueError()
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise ValueError()
            return b"".join(chunks)
        finally:
            os.close(fd)
    except Exception:
        raise MessagingConfigError("messaging_file_rejected") from None


def read_document(path: Path | str) -> Any:
    import json

    from .runtime import _unique_object

    try:
        raw = protected_read(path)
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if canonical_bytes(value) != raw:
            raise ValueError()
        return value
    except Exception:
        raise MessagingConfigError("messaging_file_rejected") from None


def _store_path(root: Path, name: str) -> Path:
    import os
    import stat

    for suffix in ("", "-wal", "-shm", "-journal"):
        path = root / (name + suffix)
        if path.is_symlink():
            raise MessagingConfigError("messaging_file_rejected")
        if path.exists():
            st = path.lstat()
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != os.geteuid()
                or st.st_mode & 0o077
                or st.st_nlink != 1
            ):
                raise MessagingConfigError("messaging_file_rejected")
    return root / name


def _compose(
    runtime: HostedRuntime,
    root: Path,
    application: Any,
    *,
    initialize: bool = False,
    metadata_root: Path | None = None,
) -> HostedRuntime:
    from dataclasses import replace

    from .local_api import LocalCapability
    from .messaging import (
        GrantReference,
        MessagingChannel,
        MessagingDelivery,
        MessagingPeerPolicy,
        MessagingSender,
    )
    from .messaging_store import MessagingInboxStore, MessagingOutboxStore
    from .operator_rebirth import authority_from_document
    from .relationship_store import RelationshipStore
    from .routes import DirectHTTPProvider, OpaqueInbox, TransportIngress
    from .runtime import MessagingHTTPContext
    from .sealed import recipient_descriptor
    from .service import MESSAGING_METHODS, MessagingServiceContext

    service = runtime.service
    # The ordinary RPC store has its own resolver/card and authorization contract.
    # Silently replacing it or maintaining a second history loses revocations.
    if service.relationships is not None:
        raise MessagingConfigError("messaging_relationship_composition_rejected")
    identity = _identity(runtime)
    custody = runtime.create_delivery_custody()
    authorities = {}
    for document in application["authorities"]:
        authority = authority_from_document(document)
        ref = authority.manifest.being_ref
        if ref in authorities:
            raise ValueError()
        authorities[ref] = authority
    local = authorities[identity["being_ref"]]
    runtime_authority = service.ledger.authority
    if not isinstance(runtime_authority, (RootAuthority, RootHistoryAuthority)):
        raise ValueError()
    if (
        local.manifest.digest != identity["manifest_hash"]
        or local.state.head != identity["control_head"]
        or local.credentials != runtime_authority.credentials
        or local.incarnations != runtime_authority.incarnations
    ):
        raise ValueError()
    incoming, outgoing = application["incoming"], application["outgoing"]
    if (
        incoming["recipient_being_ref"] != identity["being_ref"]
        or incoming["recipient_credential_id"] != identity["credential_id"]
        or outgoing["policy"]["peer_being_ref"] != identity["being_ref"]
        or outgoing["policy"]["peer_credential_id"] != identity["credential_id"]
        or outgoing["policy"]["peer_embodiment_id"] != service.origin["embodiment_id"]
        or outgoing["recipient_being_ref"] != incoming["policy"]["peer_being_ref"]
        or outgoing["recipient_credential_id"]
        != incoming["policy"]["peer_credential_id"]
        or outgoing["recipient_being_ref"] == identity["being_ref"]
    ):
        raise ValueError()
    # Resolve and bind all secrets before opening mutable stores.
    secrets = {}
    for row in [
        application["client"],
        *incoming["routes"].values(),
        *outgoing["routes"].values(),
    ]:
        raw = protected_read(root / row["secret_file"], size=32)
        if hashlib.sha256(raw).hexdigest() != row["secret_sha256"]:
            raise ValueError()
        secrets[row["secret_file"]] = raw
    if len(set(secrets.values())) != len(secrets):
        raise ValueError()
    client = application["client"]
    capability = LocalCapability.from_value(
        client["descriptor"], secrets[client["secret_file"]]
    )
    descriptor = capability.descriptor
    if (
        set(capability.methods) != MESSAGING_METHODS
        or descriptor["status"] != "active"
        or not descriptor["not_before_ms"]
        <= service.clock()
        < descriptor["not_after_ms"]
        or descriptor["not_after_ms"] - descriptor["not_before_ms"] > 30 * 86400000
        or capability.capability_id in service.capabilities
        or any(
            c.client_id == capability.client_id for c in service.capabilities.values()
        )
    ):
        raise ValueError()
    expected_client = {
        "schema": "dm.local.client-config/v3",
        "capability": descriptor,
        "expected_server": dict(service.origin),
        "runtime_id": service.runtime_id,
        "runtime_label": service.runtime_label,
    }
    if read_document((metadata_root or root) / "client.json") != expected_client:
        raise ValueError()
    if not initialize:
        for filename in application["stores"].values():
            if not (root / filename).is_file():
                raise MessagingConfigError("messaging_required_store_missing")
            if (root / filename).stat().st_size == 0:
                raise MessagingConfigError("messaging_required_store_invalid")
    stores = {
        name: _store_path(root, filename)
        for name, filename in application["stores"].items()
    }
    relationships = RelationshipStore(
        stores["relationships"],
        authority_resolver=lambda being_ref: authorities[being_ref],
    )
    if initialize:
        for event in application["relationship_events"]:
            relationships.ingest(event)

    def channel(row: Any, store: Path) -> MessagingChannel:
        policy = dict(row["policy"])
        policy["grant_refs"] = tuple(
            GrantReference(**ref) for ref in policy["grant_refs"]
        )
        result = MessagingChannel(
            policy=MessagingPeerPolicy(**policy),
            local_being_ref=row["recipient_being_ref"],
            local_credential_id=row["recipient_credential_id"],
            authority_resolver=lambda being_ref: authorities[being_ref],
            relationships=relationships,
            custody=custody,
            inbox=MessagingInboxStore(store),
            clock=service.clock,
        )
        recipient_descriptor(result._local(), at_ms=service.clock())
        from .sealed import RecipientTarget

        peer = recipient_descriptor(
            RecipientTarget(result._sender(), result.policy.peer_credential_id),
            at_ms=service.clock(),
        )
        if peer["embodiment_id"] != result.policy.peer_embodiment_id:
            raise ValueError()
        result.disclosure()  # exact current grants, membership, cards and signed events
        return result

    receiver = channel(incoming, stores["inbox"])
    context = channel(outgoing, stores["outgoing-context"])
    sender = MessagingSender(
        context=context,
        ledger=service.ledger,
        signer=service.signer,
        custody=custody,
        outbox=MessagingOutboxStore(stores["outbox"]),
        clock=service.clock,
    )
    sender._bind(service.clock())
    providers, ingresses = {}, {}
    for phase in ("evidence", "message"):
        row = outgoing["routes"][phase]
        providers[phase] = DirectHTTPProvider(
            **{k: row[k] for k in ("provider_ref", "route_ref", "key_ref", "endpoint")},
            secret=secrets[row["secret_file"]],
            route_class="direct",
            sender_principal=identity["being_ref"],
            sender_body_ref=service.origin["body_ref"],
            clock=service.clock,
        )
        row = incoming["routes"][phase]
        ingresses[phase] = TransportIngress(
            **{k: row[k] for k in ("provider_ref", "route_ref", "key_ref")},
            secret=secrets[row["secret_file"]],
            recipient_id=incoming["policy"]["membership_ref"],
            recipient_body_ref=service.origin["body_ref"],
            recipient_embodiment_id=service.origin["embodiment_id"],
            inbox=OpaqueInbox(stores["opaque-" + phase], clock=service.clock),
            clock=service.clock,
            intake_validator=getattr(receiver, "receive_" + phase),
        )
    delivery = MessagingDelivery(
        sender=sender,
        evidence_provider=providers["evidence"],
        message_provider=providers["message"],
        # Client lease renewal does not change transport replay bindings.
        config_digest=config_digest(
            {k: v for k, v in application.items() if k != "client"}
        ),
    )
    messaging = MessagingServiceContext(
        channels={incoming["channel_id"]: receiver},
        deliveries={outgoing["channel_id"]: delivery},
        client_channels={
            capability.client_id: frozenset(
                {incoming["channel_id"], outgoing["channel_id"]}
            )
        },
    )
    return replace(
        runtime,
        service=replace(
            service,
            messaging=messaging,
            capabilities={**service.capabilities, capability.capability_id: capability},
        ),
        messaging_http=MessagingHTTPContext(
            (application["listen"]["host"], application["listen"]["port"]),
            ingresses["evidence"],
            ingresses["message"],
        ),
    )


def read_publication(runtime: HostedRuntime, root: Path) -> tuple[Any, Path]:
    """Read one atomic signed publication; missing pointer never means bootstrap."""
    import re

    publication = read_document(root / "publication.json")
    if not isinstance(publication, dict) or set(publication) != {"body", "binding"}:
        raise MessagingConfigError("messaging_publication_rejected")
    body = publication["body"]
    if (
        not isinstance(body, dict)
        or set(body)
        != {"schema", "generation", "application_sha256", "predecessor_sha256"}
        or body["schema"] != "dm.messaging.publication/v1"
    ):
        raise MessagingConfigError("messaging_publication_rejected")
    generation = body["generation"]
    if not isinstance(generation, str) or (
        generation != "."
        and re.fullmatch(r"generation-[0-9a-f]{32}", generation) is None
    ):
        raise MessagingConfigError("messaging_publication_rejected")
    verify_binding(runtime, body, publication["binding"])
    metadata = root if generation == "." else _directory(root / generation)
    application = read_document(metadata / "application.json")
    validate_shape(application)
    verify_binding(runtime, application, read_document(metadata / "binding.json"))
    if config_digest(application) != body["application_sha256"]:
        raise MessagingConfigError("messaging_publication_rejected")
    return application, metadata


def load_application(
    runtime: HostedRuntime, app_directory: Path | str
) -> HostedRuntime:
    """Load signed owner-local state; no signing, enrollment or network activity."""
    try:
        root = _directory(app_directory)
        if root == runtime.state_root or runtime.state_root in root.parents:
            raise ValueError()
        application, metadata = read_publication(runtime, root)
        return _compose(runtime, root, application, metadata_root=metadata)
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_application_rejected") from None
