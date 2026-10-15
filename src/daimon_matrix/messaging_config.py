"""Signed owner-local messaging applications; not a model authorization API.

Enrollment is a trusted operator operation, separate from v7 runtime bundles.
No ordinary operator/host capability profiles or runtime schemas are extended.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authority_epochs import RootHistoryAuthority
from .canonical import b64url, canonical_bytes, unb64url
from .identity import verify_embodiment_credential, verify_incarnation_authorization
from .mandatory_echo import TABLE_SQL as ECHO_TABLE_SQL
from .native_egress import OPERATION_TABLE_SQL, OperationBinding
from .runtime import HostedRuntime
from .weave import RootAuthority

APPLICATION_SCHEMA = "dm.messaging.application/v1"
APPLICATION_SCHEMA_V2 = "dm.messaging.application/v2"
APPLICATION_SCHEMA_V3 = "dm.messaging.application/v3"
BINDING_SCHEMA = "dm.messaging.operator-binding/v1"
BINDING_DOMAIN = b"daimon/messaging-operator-binding/v1\x00"
CAPABILITY_STATE_SCHEMA = "dm.messaging.capability-state/v1"
CAPABILITY_JOURNAL_DOMAIN = b"daimon/messaging-capability-journal/v1\x00"


class MessagingConfigError(ValueError):
    """Bounded public error; never includes input values or secret bytes."""


def _public_identity(
    authority: RootAuthority | RootHistoryAuthority,
    origin: Mapping[str, Any],
    runtime_id: str,
    runtime_label: str,
    at_ms: int,
) -> dict[str, Any]:
    member = authority.validate_origin(origin, require_active=True)
    credential = authority.credentials[member["embodiment_credential_id"]]
    incarnation = authority.incarnations[member["incarnation_authorization_id"]]
    verify_embodiment_credential(credential, authority.state, at_ms=at_ms)
    verify_incarnation_authorization(
        incarnation, credential, authority.state, at_ms=at_ms
    )
    signing = credential["body"]["signing_key"]
    return {
        "runtime_id": runtime_id,
        "runtime_label": runtime_label,
        "being_ref": authority.manifest.being_ref,
        "origin": dict(origin),
        "control_head": authority.state.head,
        "manifest_hash": authority.manifest.digest,
        "credential_id": member["embodiment_credential_id"],
        "incarnation_authorization_id": member["incarnation_authorization_id"],
        "signing_key_id": signing["key_id"],
    }


def _identity(runtime: HostedRuntime) -> dict[str, Any]:
    service = runtime.service
    authority = service.ledger.authority
    if not isinstance(authority, (RootAuthority, RootHistoryAuthority)):
        raise MessagingConfigError("messaging_binding_rejected")
    identity = _public_identity(
        authority,
        service.origin,
        service.runtime_id,
        service.runtime_label,
        service.clock(),
    )
    signing = authority.credentials[identity["credential_id"]]["body"]["signing_key"]
    if signing["key_id"] != service.signer.key_id or signing["public"] != b64url(
        service.signer.public_key
    ):
        raise MessagingConfigError("messaging_binding_rejected")
    return identity


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


def _verify_public_binding(
    identity: dict[str, Any], public_key: bytes, application: Any, binding: Any
) -> None:
    try:
        if (
            not isinstance(binding, dict)
            or set(binding) != {"schema", "body", "signature"}
            or binding["schema"] != BINDING_SCHEMA
        ):
            raise ValueError()
        expected = {
            **identity,
            "application_sha256": config_digest(application),
        }
        if binding["body"] != expected:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            unb64url(binding["signature"], length=64),
            BINDING_DOMAIN + canonical_bytes(expected),
        )
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


def verify_public_binding(
    identity: Mapping[str, Any], public_key: bytes, document: Any, binding: Any
) -> None:
    """Narrow public verifier for detached operator-binding/v1 documents."""

    _verify_public_binding(dict(identity), public_key, document, binding)


def verify_binding(runtime: HostedRuntime, application: Any, binding: Any) -> None:
    try:
        _verify_public_binding(
            _identity(runtime), runtime.service.signer.public_key, application, binding
        )
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


def verify_binding_within_history(
    runtime: HostedRuntime, value: Any, binding: Any
) -> None:
    """Verify one append-only owner-local record against its own verified epoch.

    Enrolling another embodiment advances the being manifest, while every record
    this runtime already authenticated names the manifest digest it was written
    under. Demanding the current digest there would invalidate an append-only
    journal that the same runtime signing key produced, so adding one body would
    force a rewrite of authenticated history. The record is instead verified
    exactly against the verified epoch whose manifest digest it names, at the time
    it claims: an unknown digest, a changed body, an expired credential or a bad
    signature still fails closed. Current-state documents such as an application
    publication or a visibility installation keep requiring the current epoch.
    """
    try:
        if not isinstance(binding, Mapping) or set(binding) != {
            "schema",
            "body",
            "signature",
        }:
            raise ValueError()
        body = binding["body"]
        if not isinstance(body, Mapping):
            raise ValueError()
        authority = runtime.service.ledger.authority
        epoch: RootAuthority
        if isinstance(authority, RootHistoryAuthority):
            epoch = authority.select(body)
        else:
            if authority.manifest.digest != body.get("manifest_hash"):
                raise ValueError()
            epoch = cast(RootAuthority, authority)
        occurred_at = body.get("occurred_at_ms")
        at_ms = occurred_at if type(occurred_at) is int else runtime.service.clock()
        identity = _public_identity(
            epoch,
            runtime.service.origin,
            runtime.service.runtime_id,
            runtime.service.runtime_label,
            at_ms,
        )
        credential = epoch.credentials[identity["credential_id"]]
        public_key = unb64url(credential["body"]["signing_key"]["public"], length=32)
        _verify_public_binding(identity, public_key, value, binding)
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


def verify_record_binding(runtime: HostedRuntime, value: Any, binding: Any) -> None:
    """Authenticate a retained body record at its signed recording time.

    An expired credential cannot authorize new effects, but its expiration must
    not erase an authenticated record it signed while valid. Historical identity
    must name the same being and body; incarnation/credential renewal is retained
    evidence, never permission to send with an obsolete credential.
    """
    try:
        instant, body = value["recorded_at_ms"], binding["body"]
        authority = runtime.service.ledger.authority
        if not isinstance(authority, (RootAuthority, RootHistoryAuthority)):
            raise ValueError()
        if (
            type(instant) is not int
            or not 0 <= instant <= runtime.service.clock()
            or body["being_ref"] != authority.manifest.being_ref
            or any(
                body["origin"][key] != runtime.service.origin[key]
                for key in ("body_ref", "embodiment_id")
            )
        ):
            raise ValueError()
        epoch = (
            authority.select(body)
            if isinstance(authority, RootHistoryAuthority)
            else authority
        )
        identity = _public_identity(
            epoch, body["origin"], body["runtime_id"], body["runtime_label"], instant
        )
        credential = epoch.credentials[identity["credential_id"]]
        public_key = unb64url(credential["body"]["signing_key"]["public"], length=32)
        _verify_public_binding(identity, public_key, value, binding)
    except Exception:
        raise MessagingConfigError("messaging_binding_rejected") from None


def verify_visibility_participant(
    authority: RootAuthority | RootHistoryAuthority,
    participant: str,
    document: Any,
    binding: Any,
    *,
    at_ms: int,
) -> None:
    """Keep an unchanged disclosure's acceptance across a verified succession.

    Authenticate the binding in its exact epoch, then require the same body and
    credential to remain valid and active now. V1 bindings have no signing time;
    disclosure issuance does not establish one. An earlier
    incarnation may have ended; retirement or key replacement is not consent by
    the new body. No receipt or caller timestamp selects the historical epoch.
    """
    try:
        body = binding["body"]
        epoch = (
            authority.select(body)
            if isinstance(authority, RootHistoryAuthority)
            else authority
        )
        active = (
            authority.active
            if isinstance(authority, RootHistoryAuthority)
            else authority
        )
        instant = document["issued_at_ms"]
        if type(instant) is not int or not 0 <= instant <= at_ms or instant >= 2**53:
            raise ValueError()
        if epoch.manifest.being_ref != participant or body["being_ref"] != participant:
            raise ValueError()
        identity = _public_identity(
            epoch,
            body["origin"],
            body["runtime_id"],
            body["runtime_label"],
            at_ms,
        )
        credential = epoch.credentials[identity["credential_id"]]
        public_key = unb64url(credential["body"]["signing_key"]["public"], length=32)
        verify_public_binding(identity, public_key, document, binding)
        members = [
            row
            for row in active.manifest.value["embodiments"]
            if row["status"] == "active"
            and row["embodiment_id"] == body["origin"]["embodiment_id"]
            and row["body_ref"] == body["origin"]["body_ref"]
            and row["embodiment_credential_id"] == identity["credential_id"]
        ]
        if len(members) != 1:
            raise ValueError()
        member = members[0]
        current_origin = {**body["origin"], "incarnation_id": member["incarnation_id"]}
        current = _public_identity(
            active, current_origin, body["runtime_id"], body["runtime_label"], at_ms
        )
        if active.credentials[current["credential_id"]] != credential:
            raise ValueError()
    except Exception:
        raise MessagingConfigError(
            "messaging_visibility_installation_rejected"
        ) from None


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
        **{
            k: {**_TEXT, "type": ["string", "null"]}
            for k in ("tribe_ref", "membership_ref")
        },
        "operation": {"enum": ["read", "messaging.read"]},
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
# A tribe channel's policy. Closed, and closed on purpose: there is no
# resource_ref, no operation and no grant_refs here, so a configuration that
# supplies one is rejected by the schema instead of being carried into an
# envelope. Recipients are not configured either -- they are resolved from
# verified membership at send time and frozen into the signed resolution.
_TRIBE_POLICY = _object(
    {
        "tribe_ref": _TEXT,
        "membership_ref": _TEXT,
        "classification": {"enum": ["private", "shareable", "public"]},
        "max_ttl_ms": {"type": "integer", "minimum": 1, "maximum": 60000},
    }
)
_TRIBE_CHANNEL = _object(
    {
        "channel_id": _LEAF,
        "policy": _TRIBE_POLICY,
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


# Optional signed composition contract. Absent means the original isolated mode.
# stores.relationships remains a reserved app-local leaf, never opened in shared
# mode. The separate binding below names the exact ordinary store instead.
for _application_schema in (SPECIFICATION_SCHEMA, APPLICATION_JSON_SCHEMA):
    _application_schema["properties"]["relationship_mode"] = _object(
        {
            "mode": {"const": "shared"},
            "runtime_id": _TEXT,
            "state_root": {"type": "string", "minLength": 1, "maxLength": 4096},
            "store_filename": _LEAF,
        }
    )


# Optional tribe channel. Absent means the application has only its pairwise
# lane, so every existing configuration stays valid. Added to `properties`
# without being added to `required`, which is how `relationship_mode` above is
# optional too.
for _application_schema in (SPECIFICATION_SCHEMA, APPLICATION_JSON_SCHEMA):
    _application_schema["properties"]["tribe"] = _TRIBE_CHANNEL

GROUP_STORE_NAMES = ("records", "envelopes", "opaque-evidence", "opaque-message")
GROUP_SPECIFICATION_SCHEMA = _object(
    {
        "schema": {"const": APPLICATION_SCHEMA_V3},
        "listen": SPECIFICATION_SCHEMA["properties"]["listen"],
        "authorities": {
            **SPECIFICATION_SCHEMA["properties"]["authorities"],
            "minItems": 1,
        },
        "relationship_events": SPECIFICATION_SCHEMA["properties"][
            "relationship_events"
        ],
        "relationship_mode": SPECIFICATION_SCHEMA["properties"]["relationship_mode"],
        "tribe": _TRIBE_CHANNEL,
        "intake": _ROUTE,
        "roster": {
            "type": "array",
            "minItems": 1,
            "maxItems": 256,
            "items": _object(
                {
                    "being_ref": _TEXT,
                    "embodiment_id": _TEXT,
                    "body_ref": _TEXT,
                    "route": _ROUTE,
                }
            ),
        },
        "stores": _object({name: _LEAF for name in GROUP_STORE_NAMES}),
    }
)
GROUP_APPLICATION_SCHEMA = _object(
    {
        **GROUP_SPECIFICATION_SCHEMA["properties"],
        "client": APPLICATION_JSON_SCHEMA["properties"]["client"],
    }
)


def application_routes(application: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Transport registrations, never conversation membership or recipients."""
    if application["schema"] == APPLICATION_SCHEMA_V3:
        return [application["intake"], *[row["route"] for row in application["roster"]]]
    return [
        route
        for direction in ("incoming", "outgoing")
        for route in application[direction]["routes"].values()
    ]


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
    if kind == ["string", "null"]:
        if value is None:
            return
        kind = "string"
    if kind == "object":
        if not isinstance(value, dict):
            raise ValueError()
        if "properties" in schema:
            if not set(schema["required"]).issubset(value) or not set(value).issubset(
                schema["properties"]
            ):
                raise ValueError()
            for name in value:
                _shape(value[name], schema["properties"][name])
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
        import copy

        group = (
            isinstance(application, dict)
            and application.get("schema") == APPLICATION_SCHEMA_V3
        )
        shape = copy.deepcopy(
            (GROUP_SPECIFICATION_SCHEMA if specification else GROUP_APPLICATION_SCHEMA)
            if group
            else (SPECIFICATION_SCHEMA if specification else APPLICATION_JSON_SCHEMA)
        )
        if (
            isinstance(application, dict)
            and application.get("schema") == APPLICATION_SCHEMA_V2
        ):
            shape["properties"]["schema"] = {"const": APPLICATION_SCHEMA_V2}
        _shape(application, shape)
        if group:
            _validate_group_shape(application, specification=specification)
            return
        for direction in ("incoming", "outgoing"):
            policy = application[direction]["policy"]
            if (policy["tribe_ref"] is None) != (policy["membership_ref"] is None):
                raise ValueError()
        # Numeric addresses only: no resolver changes to listener binding.
        import ipaddress
        from urllib.parse import urlsplit

        ipaddress.IPv4Address(application["listen"]["host"])
        if (
            application["incoming"]["channel_id"]
            == application["outgoing"]["channel_id"]
        ):
            raise ValueError()
        tribe_section = application.get("tribe")
        if isinstance(tribe_section, dict) and tribe_section.get("channel_id") in {
            application["incoming"]["channel_id"],
            application["outgoing"]["channel_id"],
        }:
            # One channel id means one channel. A tribe channel sharing an id
            # with either pairwise direction would make the uniform surface
            # ambiguous about which lane a send belongs to.
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


def _validate_group_shape(application: Any, *, specification: bool) -> None:
    import ipaddress
    from urllib.parse import urlsplit

    ipaddress.IPv4Address(application["listen"]["host"])
    seen = set()
    names = [
        "application.json",
        "binding.json",
        "client.json",
        "client.key",
        "publication.json",
        *application["stores"].values(),
    ]
    for route in application_routes(application):
        endpoint = urlsplit(route["endpoint"])
        if (
            endpoint.scheme not in {"http", "https"}
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query
            or endpoint.fragment
            or endpoint.port is None
            or endpoint.path != "/dm-messaging/v1/message"
        ):
            raise ValueError()
        # The selected group profile bounds network attempts without DNS/NSS
        # work. Legacy directed hostname adapters remain a separate profile.
        ipaddress.ip_address(endpoint.hostname)
        if "%" in endpoint.hostname:
            raise ValueError()
    for row in application["roster"]:
        key = (row["being_ref"], row["embodiment_id"])
        if key in seen:
            raise ValueError()
        seen.add(key)
    intake = urlsplit(application["intake"]["endpoint"])
    if (
        intake.scheme != "http"
        or intake.hostname != application["listen"]["host"]
        or intake.port != application["listen"]["port"]
    ):
        raise ValueError()
    # One body registration key may occur both in the roster and local intake.
    files: dict[str, str] = {}
    for row in application_routes(application):
        prior = files.setdefault(row["secret_file"], row["secret_sha256"])
        if prior != row["secret_sha256"]:
            raise ValueError()
    names += list(files)
    if len(set(names)) != len(names):
        raise ValueError()
    if not specification and application["client"]["secret_file"] != "client.key":
        raise ValueError()


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


def capability_journal_identity(
    runtime: HostedRuntime, descriptor: Mapping[str, Any]
) -> str:
    """Stable owner-local journal identity for one runtime/client lane."""
    core = {
        "runtime_id": runtime.service.runtime_id,
        "client_id": descriptor["client_id"],
    }
    return (
        "dm:capability-journal:v1:"
        + hashlib.sha256(CAPABILITY_JOURNAL_DOMAIN + canonical_bytes(core)).hexdigest()
    )


def _capability_journal_names(
    runtime: HostedRuntime, descriptor: Mapping[str, Any]
) -> tuple[str, str]:
    identity = capability_journal_identity(runtime, descriptor)
    stem = ".messaging-capability-" + hashlib.sha256(identity.encode()).hexdigest()
    return identity, stem


def capability_state_record(
    runtime: HostedRuntime,
    descriptor: Mapping[str, Any],
    *,
    sequence: int,
    predecessor_sha256: str | None,
    action: str,
    occurred_at_ms: int,
) -> dict[str, Any]:
    """Create one runtime-authenticated monotonic capability-state record."""
    identity, _ = _capability_journal_names(runtime, descriptor)
    body = {
        "schema": CAPABILITY_STATE_SCHEMA,
        "journal_identity": identity,
        "runtime_id": runtime.service.runtime_id,
        "sequence": sequence,
        "predecessor_sha256": predecessor_sha256,
        "action": action,
        "capability_id": descriptor["capability_id"],
        "client_id": descriptor["client_id"],
        "key_id": descriptor["key_id"],
        "descriptor_sha256": config_digest(descriptor),
        "occurred_at_ms": occurred_at_ms,
    }
    return {"body": body, "binding": create_binding(runtime, body)}


def _capability_state_chain(
    runtime: HostedRuntime,
    descriptor: Mapping[str, Any],
) -> tuple[str, str, list[tuple[dict[str, Any], bytes]]]:
    """Verify and return the immutable authenticated journal, ignoring write temps."""
    import re

    try:
        identity, stem = _capability_journal_names(runtime, descriptor)
        root = _directory(runtime.state_root)
        pointer_temporary = re.compile(
            rf"^{re.escape(stem)}-(?:current|floor)-[0-9a-f]{{32}}\.json$"
        )
        entries: list[tuple[int, Path]] = []
        for path in root.iterdir():
            name = path.name
            if name in {stem + "-current.json", stem + "-floor.json"}:
                continue
            if pointer_temporary.fullmatch(name):
                continue
            if not name.startswith(stem + "-") or not name.endswith(".json"):
                continue
            suffix = name[len(stem) + 1 : -5]
            if len(suffix) != 20 or not suffix.isdecimal():
                raise ValueError()
            entries.append((int(suffix), path))
        entries.sort()
        if not entries or [number for number, _ in entries] != list(
            range(len(entries))
        ):
            raise ValueError()
        previous_hash: str | None = None
        previous_body: Mapping[str, Any] | None = None
        chain: list[tuple[dict[str, Any], bytes]] = []
        for expected_sequence, path in entries:
            raw = protected_read(path)
            record = read_document(path)
            if not isinstance(record, Mapping) or set(record) != {"body", "binding"}:
                raise ValueError()
            body = record["body"]
            if not isinstance(body, Mapping) or set(body) != {
                "schema",
                "journal_identity",
                "runtime_id",
                "sequence",
                "predecessor_sha256",
                "action",
                "capability_id",
                "client_id",
                "key_id",
                "descriptor_sha256",
                "occurred_at_ms",
            }:
                raise ValueError()
            verify_binding_within_history(runtime, body, record["binding"])
            if (
                body["schema"] != CAPABILITY_STATE_SCHEMA
                or body["journal_identity"] != identity
                or body["runtime_id"] != runtime.service.runtime_id
                or body["sequence"] != expected_sequence
                or body["predecessor_sha256"] != previous_hash
                or body["client_id"] != descriptor["client_id"]
                or body["key_id"] != descriptor["key_id"]
                or type(body["occurred_at_ms"]) is not int
                or body["occurred_at_ms"] < 0
                or body["action"] not in {"activate", "replace", "revoke"}
                or (expected_sequence == 0) != (body["action"] == "activate")
                or (
                    previous_body is not None
                    and (
                        body["occurred_at_ms"] < previous_body["occurred_at_ms"]
                        or previous_body["action"] == "revoke"
                        or (
                            body["action"] == "revoke"
                            and any(
                                body[field] != previous_body[field]
                                for field in (
                                    "capability_id",
                                    "client_id",
                                    "key_id",
                                    "descriptor_sha256",
                                )
                            )
                        )
                        or (
                            body["action"] == "replace"
                            and (
                                body["capability_id"] == previous_body["capability_id"]
                                or body["descriptor_sha256"]
                                == previous_body["descriptor_sha256"]
                            )
                        )
                    )
                )
            ):
                raise ValueError()
            copied_body = dict(body)
            chain.append((copied_body, raw))
            previous_hash = hashlib.sha256(raw).hexdigest()
            previous_body = copied_body
        return identity, stem, chain
    except MessagingConfigError as exception:
        if str(exception) == "messaging_capability_state_rejected":
            raise
        raise MessagingConfigError("messaging_capability_state_rejected") from None
    except Exception:
        raise MessagingConfigError("messaging_capability_state_rejected") from None


def read_capability_state(
    runtime: HostedRuntime,
    descriptor: Mapping[str, Any],
    *,
    require_active: bool = True,
) -> dict[str, Any]:
    """Verify the complete retained chain and exact durable high-water record."""
    try:
        _identity, stem, chain = _capability_state_chain(runtime, descriptor)
        latest_body, latest_raw = chain[-1]
        root = _directory(runtime.state_root)
        current = protected_read(root / (stem + "-current.json"))
        floor = protected_read(root / (stem + "-floor.json"))
        if current != latest_raw or floor != latest_raw:
            raise ValueError()
        expected = {
            "capability_id": descriptor["capability_id"],
            "client_id": descriptor["client_id"],
            "key_id": descriptor["key_id"],
            "descriptor_sha256": config_digest(descriptor),
        }
        if any(latest_body[field] != value for field, value in expected.items()):
            raise MessagingConfigError("messaging_capability_stale")
        if latest_body["action"] == "revoke":
            if require_active:
                raise MessagingConfigError("messaging_capability_revoked")
        elif latest_body["action"] not in {"activate", "replace"}:
            raise ValueError()
        return dict(latest_body)
    except MessagingConfigError as exception:
        if str(exception) in {
            "messaging_capability_revoked",
            "messaging_capability_stale",
        }:
            raise
        raise MessagingConfigError("messaging_capability_state_rejected") from None
    except Exception:
        raise MessagingConfigError("messaging_capability_state_rejected") from None


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


# Pinned constructor schemas: relationship_store, messaging_store and routes.
# Only trusted staging may create them. Changes require explicit loader review;
# published loading is deliberately not a migration/repair path.
_STORE_SCHEMA_SQL = {
    "relationships": """
        CREATE TABLE IF NOT EXISTS metadata ( key TEXT PRIMARY KEY, value TEXT NOT
        NULL ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS events ( event_id TEXT NOT NULL, content_hash
        TEXT NOT NULL, being_ref TEXT NOT NULL, embodiment_id TEXT NOT NULL,
        incarnation_id TEXT NOT NULL, sequence INTEGER NOT NULL, kind TEXT NOT NULL,
        subject TEXT NOT NULL, event_json BLOB NOT NULL, inserted_order INTEGER
        PRIMARY KEY AUTOINCREMENT, UNIQUE(event_id, content_hash) );
        CREATE INDEX IF NOT EXISTS relationship_event_id ON events(event_id);
        CREATE INDEX IF NOT EXISTS relationship_origin_position ON events(being_ref,
        incarnation_id, sequence);
        CREATE INDEX IF NOT EXISTS relationship_kind_subject ON events(kind,
        subject);
        CREATE TABLE IF NOT EXISTS operations ( request_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL, event_id TEXT NOT NULL, content_hash TEXT NOT
        NULL ) WITHOUT ROWID;
    """,
    "inbox": """
        CREATE TABLE IF NOT EXISTS deliveries ( delivery_id TEXT PRIMARY KEY,
        bytes_hash TEXT NOT NULL );
        CREATE TABLE IF NOT EXISTS identities ( event_id TEXT PRIMARY KEY, being_ref
        TEXT NOT NULL, incarnation_id TEXT NOT NULL, sequence INTEGER NOT NULL,
        bytes_hash TEXT NOT NULL, UNIQUE(being_ref, incarnation_id, sequence) );
        CREATE TABLE IF NOT EXISTS evidence ( message_id TEXT NOT NULL,
        authorization_id TEXT NOT NULL, policy_hash TEXT NOT NULL, event BLOB NOT
        NULL, envelope BLOB NOT NULL, PRIMARY KEY(message_id, authorization_id) );
        CREATE TABLE IF NOT EXISTS inbox ( inbox_sequence INTEGER PRIMARY KEY
        AUTOINCREMENT, message_id TEXT NOT NULL UNIQUE, policy_hash TEXT NOT NULL,
        message BLOB NOT NULL, evidence BLOB NOT NULL, envelope BLOB NOT NULL,
        admission_version INTEGER NOT NULL DEFAULT 1
        CHECK(admission_version IN (1, 2)) );
    """,
    "outbox": """
        CREATE TABLE IF NOT EXISTS messaging_outbox ( owner TEXT NOT NULL, send_id
        TEXT NOT NULL, plan BLOB NOT NULL, evidence BLOB, message BLOB, PRIMARY
        KEY(owner, send_id), CHECK ((evidence IS NULL) = (message IS NULL)) );
        CREATE TABLE IF NOT EXISTS messaging_transport_stages ( owner TEXT NOT NULL,
        send_id TEXT NOT NULL, phase TEXT NOT NULL CHECK (phase IN ('evidence',
        'message')), binding BLOB NOT NULL, request BLOB NOT NULL, request_sha256
        TEXT NOT NULL, transport_status TEXT NOT NULL CHECK (transport_status IN
        ('prepared', 'pending', 'recipient-intake', 'refused', 'hub-accepted')),
        result_sha256 TEXT, response BLOB, PRIMARY KEY(owner, send_id, phase) );
    """,
    "opaque": """
        CREATE TABLE IF NOT EXISTS inbox_meta (singleton INTEGER PRIMARY KEY
        CHECK(singleton=1), next_sequence INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS inbox_items (sequence INTEGER PRIMARY KEY,
        delivery_id TEXT UNIQUE NOT NULL, recipient_id TEXT NOT NULL, envelope_hash
        TEXT NOT NULL, envelope BLOB NOT NULL, received_at_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('pending','acked')), claim_id TEXT,
        consumer_id TEXT, lease_until_ms INTEGER);
        CREATE TABLE IF NOT EXISTS inbox_requests (request_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL, delivery_id TEXT NOT NULL, response BLOB,
        response_sha256 TEXT, egress_path_id TEXT);
        CREATE TABLE IF NOT EXISTS inbox_tombstones (delivery_id TEXT PRIMARY KEY,
        recipient_id TEXT NOT NULL, envelope_hash TEXT NOT NULL, received_at_ms
        INTEGER NOT NULL, sequence INTEGER NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS inbox_claims (claim_id TEXT PRIMARY KEY,
        request_hash TEXT NOT NULL, result_json BLOB NOT NULL);
    """,
}

_STORE_SCHEMA_SQL["records"] = """
    CREATE TABLE IF NOT EXISTS tribe_records (
        kind TEXT NOT NULL, record_id TEXT NOT NULL, request_hash TEXT NOT NULL,
        document BLOB NOT NULL, binding BLOB NOT NULL, document_hash TEXT NOT NULL,
        recorded_at_ms INTEGER NOT NULL,
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, UNIQUE(kind,record_id));
"""
_STORE_SCHEMA_SQL["envelopes"] = """
    CREATE TABLE IF NOT EXISTS envelopes (
        request_id TEXT PRIMARY KEY, plan_hash TEXT NOT NULL,
        envelope BLOB NOT NULL, envelope_hash TEXT NOT NULL);
"""
_STORE_SCHEMA_SQL_WITHOUT_VISIBILITY = dict(_STORE_SCHEMA_SQL)
_EGRESS_SCHEMA_SQL = ";".join((OPERATION_TABLE_SQL, *ECHO_TABLE_SQL.values(), ""))
for _egress_store in ("outbox", "opaque", "records"):
    _STORE_SCHEMA_SQL[_egress_store] += _EGRESS_SCHEMA_SQL

_LEGACY_INBOX_SCHEMA_SQL = _STORE_SCHEMA_SQL["inbox"].replace(
    ",\n        admission_version INTEGER NOT NULL DEFAULT 1\n        "
    "CHECK(admission_version IN (1, 2))",
    "",
)


def _validate_store_schema(
    name: str,
    path: Path,
    *,
    require_inbox_admission: bool = False,
    allow_missing_visibility: bool = False,
) -> None:
    """Inspect published state without DDL, recovery, or sidecar creation."""
    import re
    import sqlite3
    from contextlib import closing

    from .relationship_store import SCHEMA_VERSION

    def catalog(db: sqlite3.Connection) -> list[tuple[Any, ...]]:
        # Preserve quoted literals and token boundaries, ignoring only spacing.
        # Table SQL binds CHECK/PK/UNIQUE/NOT NULL, AUTOINCREMENT, WITHOUT ROWID;
        # catalog index entries also require the backing unique/ordinary indexes.
        return [
            (kind, table, name, re.findall(r"'(?:''|[^'])*'|\w+|[^\s]", sql or ""))
            for kind, table, name, sql in db.execute(
                "SELECT type, tbl_name, name, sql FROM sqlite_schema ORDER BY name"
            )
        ]

    try:
        # These stores use DELETE journals. Never ignore pending WAL/journal state
        # or let SQLite create/recover sidecars during validation. A busy/crashed
        # store needs a separate trusted recovery decision, not implicit repair.
        if any(
            path.with_name(path.name + suffix).exists()
            for suffix in ("-journal", "-wal", "-shm")
        ):
            raise ValueError()
        schema = (
            "opaque"
            if name.startswith("opaque-")
            else "inbox"
            if name == "outgoing-context"
            else name
        )
        with (
            closing(
                sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
            ) as db,
            closing(sqlite3.connect(":memory:")) as expected,
            closing(sqlite3.connect(":memory:")) as legacy,
        ):
            # DDL is confined to anonymous in-memory references, never a store.
            # No store constructor is used even for these references.
            expected.executescript(_STORE_SCHEMA_SQL[schema])
            expected_catalogs = [catalog(expected)]
            if allow_missing_visibility and schema in {"outbox", "opaque", "records"}:
                legacy.executescript(_STORE_SCHEMA_SQL_WITHOUT_VISIBILITY[schema])
                expected_catalogs.append(catalog(legacy))
            elif schema == "inbox" and not require_inbox_admission:
                legacy.executescript(_LEGACY_INBOX_SCHEMA_SQL)
                expected_catalogs.append(catalog(legacy))
            if (
                catalog(db) not in expected_catalogs
                or db.execute("PRAGMA user_version").fetchone() != (0,)
                or db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
            ):
                raise ValueError()
            if name == "relationships" and db.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchall() != [(str(SCHEMA_VERSION),)]:
                raise ValueError()
            if schema == "opaque":
                rows = db.execute(
                    "SELECT singleton, next_sequence FROM inbox_meta"
                ).fetchall()
                if (
                    len(rows) != 1
                    or rows[0][0] != 1
                    or type(rows[0][1]) is not int
                    or rows[0][1] < 1
                ):
                    raise ValueError()
    except (sqlite3.Error, ValueError):
        raise MessagingConfigError("messaging_required_store_invalid") from None


def _compose(
    runtime: HostedRuntime,
    root: Path,
    application: Any,
    *,
    initialize: bool = False,
    metadata_root: Path | None = None,
    capability_predecessor: Mapping[str, Any] | None = None,
) -> HostedRuntime:
    if application["schema"] == APPLICATION_SCHEMA_V3:
        return _compose_group(
            runtime,
            root,
            application,
            initialize=initialize,
            metadata_root=metadata_root,
            capability_predecessor=capability_predecessor,
        )
    if application.get("tribe") is not None:
        raise MessagingConfigError("messaging_group_application_required")
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
    if not runtime.egress.release_enabled and runtime.egress.catalog_mode != "migrate":
        raise MessagingConfigError("messaging_visibility_required")
    # The ordinary RPC store has its own resolver/card and authorization contract.
    # Silently replacing it or maintaining a second history loses revocations.
    shared = application.get("relationship_mode")
    ordinary = service.relationships
    if shared is None and ordinary is not None:
        raise MessagingConfigError("messaging_relationship_composition_rejected")
    if shared is not None:
        if (
            ordinary is None
            or ordinary.authority_resolver is None
            or shared
            != {
                "mode": "shared",
                "runtime_id": service.runtime_id,
                "state_root": str(runtime.state_root),
                "store_filename": ordinary.store.path.name,
            }
            or ordinary.store.path != runtime.state_root / shared["store_filename"]
        ):
            raise MessagingConfigError("messaging_relationship_composition_rejected")
        _directory(runtime.state_root)
        path = _store_path(runtime.state_root, shared["store_filename"])
        if not path.is_file():
            raise MessagingConfigError("messaging_required_store_missing")
        _validate_store_schema("relationships", path)
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
    resolve_authority: Callable[[str], RootAuthority | RootHistoryAuthority]
    if shared is not None:
        assert ordinary is not None and ordinary.authority_resolver is not None
        for ref, approved in authorities.items():
            if ordinary.authority_resolver(ref) != approved:
                raise MessagingConfigError("messaging_relationship_authority_mismatch")
        resolve_authority = ordinary.authority_resolver
        relationships = ordinary.store
        # No bootstrap replay, even during prepare: the trusted host must have
        # already ingested every enrollment event. Failure never modifies this DB.
        retained = {canonical_bytes(event) for event in relationships.events()}
        for event in application["relationship_events"]:
            relationships._validated_event(event)
            if canonical_bytes(event) not in retained:
                raise MessagingConfigError("messaging_shared_history_incomplete")
    else:

        def standalone_authority(
            being_ref: str,
        ) -> RootAuthority | RootHistoryAuthority:
            # The selected local epoch was checked against this runtime above.
            # Retained signed relationship events still verify in their own
            # accepted epoch; they must not be rebound to the current manifest.
            return (
                runtime_authority
                if being_ref == identity["being_ref"]
                else authorities[being_ref]
            )

        resolve_authority = standalone_authority

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
        or descriptor["schema"] != "dm.local.capability/v2"
        or descriptor["status"] != "active"
        or not capability.active_at(service.clock())
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
    if capability_predecessor is None:
        read_capability_state(runtime, descriptor)
    else:
        state = read_capability_state(runtime, capability_predecessor)
        if (
            state["capability_id"] != capability_predecessor["capability_id"]
            or capability_predecessor["client_id"] != descriptor["client_id"]
            or capability_predecessor["key_id"] != descriptor["key_id"]
        ):
            raise MessagingConfigError("messaging_capability_state_rejected")
    selected_stores = _selected_store_files(application)
    if not initialize:
        for filename in selected_stores.values():
            if not (root / filename).is_file():
                raise MessagingConfigError("messaging_required_store_missing")
            if (root / filename).stat().st_size == 0:
                raise MessagingConfigError("messaging_required_store_invalid")
    stores = {
        name: _store_path(root, filename) for name, filename in selected_stores.items()
    }
    if not initialize:
        # Validate every store before the first constructor can initialize anything.
        for name, path in stores.items():
            _validate_store_schema(
                name,
                path,
                require_inbox_admission=application["schema"] == APPLICATION_SCHEMA_V2,
                allow_missing_visibility=runtime.egress.catalog_mode == "migrate",
            )
    if shared is None:
        relationships = RelationshipStore(
            stores["relationships"],
            authority_resolver=lambda being_ref: resolve_authority(being_ref),
        )
        if initialize:
            for event in application["relationship_events"]:
                relationships.ingest(event)

    def channel_authority(being_ref: str) -> RootAuthority | RootHistoryAuthority:
        """History-preserving resolver for one channel, narrowed to root authorities.

        The store resolver keeps verified epochs so a card issued before a manifest
        advance still verifies against the epoch it pins. Anything else is refused
        rather than silently treated as the current epoch.
        """
        resolver = relationships.authority_resolver
        resolved = (
            resolver(being_ref)
            if resolver is not None
            else resolve_authority(being_ref)
        )
        if not isinstance(resolved, (RootAuthority, RootHistoryAuthority)):
            raise MessagingConfigError("messaging_relationship_authority_mismatch")
        return resolved

    def channel(row: Any, store: Path) -> MessagingChannel:
        policy = dict(row["policy"])
        policy["grant_refs"] = tuple(
            GrantReference(**ref) for ref in policy["grant_refs"]
        )
        result = MessagingChannel(
            policy=MessagingPeerPolicy(**policy),
            local_being_ref=row["recipient_being_ref"],
            local_credential_id=row["recipient_credential_id"],
            authority_resolver=channel_authority,
            relationships=relationships,
            custody=custody,
            inbox=MessagingInboxStore(store),
            clock=service.clock,
        )
        if service.labels is not None:
            entries: list[dict[str, Any]] = []
            for being_ref in (result.local_being_ref, result.policy.peer_being_ref):
                authority = result._active(being_ref)
                entries.extend(
                    {
                        "being_ref": being_ref,
                        "body_ref": member["body_ref"],
                        "embodiment_id": member["embodiment_id"],
                    }
                    for member in authority.manifest.value["embodiments"]
                    if member["status"] == "active"
                )
            result.labels = service.labels._with_verified_entries(entries)
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
        egress=runtime.egress,
        egress_catalog_id="messaging-outbox",
    )
    sender._bind(service.clock())
    communication = service.communication
    assert communication is not None
    if application["schema"] == APPLICATION_SCHEMA_V2:
        if not communication.receipts_v2:
            raise MessagingConfigError("messaging_semantic_migration_required")
        communication.foreign_authority_resolver = channel_authority
        sender.communication = communication
        receiver.communication = communication
        receiver.reconcile_receipts()
    elif communication.receipts_v2:
        raise MessagingConfigError("messaging_semantic_migration_required")
    providers, ingresses = {}, {}
    ingress_authority_head = service.origin["body_ref"]
    if not isinstance(ingress_authority_head, str):
        raise MessagingConfigError("messaging_identity_rejected")

    def authorize_ingress_egress(binding: OperationBinding) -> bool:
        return binding.authority_head == ingress_authority_head

    for phase in ("evidence", "message"):
        row = outgoing["routes"][phase]
        providers[phase] = DirectHTTPProvider(
            **{k: row[k] for k in ("provider_ref", "route_ref", "key_ref", "endpoint")},
            secret=secrets[row["secret_file"]],
            route_class="direct",
            sender_principal=identity["being_ref"],
            sender_body_ref=service.origin["body_ref"],
            clock=service.clock,
            egress=runtime.egress,
        )
        row = incoming["routes"][phase]
        ingresses[phase] = TransportIngress(
            **{k: row[k] for k in ("provider_ref", "route_ref", "key_ref")},
            secret=secrets[row["secret_file"]],
            recipient_id=receiver.policy.recipient_id,
            recipient_body_ref=service.origin["body_ref"],
            recipient_embodiment_id=service.origin["embodiment_id"],
            inbox=OpaqueInbox(stores["opaque-" + phase], clock=service.clock),
            clock=service.clock,
            egress=runtime.egress,
            egress_catalog_id=f"messaging-{phase}-responses",
            egress_authority_head=ingress_authority_head,
            egress_authorizer=authorize_ingress_egress,
            intake_validator=getattr(receiver, "receive_" + phase),
        )
    delivery = MessagingDelivery(
        sender=sender,
        evidence_provider=providers["evidence"],
        message_provider=providers["message"],
        config_digest=_transport_config_digest(application),
        historical_inspection=lambda retained: _verify_historical_transport(
            runtime, root, application, retained
        ),
    )

    def capability_guard(selected: LocalCapability) -> None:
        if selected.capability_id != capability.capability_id:
            raise ValueError()
        read_capability_state(runtime, selected.descriptor)

    messaging = MessagingServiceContext(
        channels={incoming["channel_id"]: receiver},
        deliveries={outgoing["channel_id"]: delivery},
        client_channels={
            capability.client_id: frozenset(
                {incoming["channel_id"], outgoing["channel_id"]}
            )
        },
        capability_guard=capability_guard,
        labels=service.labels,
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


def _compose_group(
    runtime: HostedRuntime,
    root: Path,
    application: Any,
    *,
    initialize: bool,
    metadata_root: Path | None,
    capability_predecessor: Mapping[str, Any] | None,
) -> HostedRuntime:
    from dataclasses import replace

    from .local_api import LocalCapability
    from .messaging import GroupMessaging, MessagingTribePolicy
    from .messaging_store import TribeRecordStore
    from .operator_rebirth import authority_from_document
    from .routes import DirectHTTPProvider, OpaqueInbox, TransportIngress
    from .runtime import MessagingHTTPContext
    from .sealed import EnvelopeStore
    from .service import (
        MESSAGING_METHODS,
        RECEIVING_CONTROL_METHODS,
        LoadedStoreBinding,
        MessagingServiceContext,
        ReceivingServiceContext,
    )
    from .tribe_conversation import TribeConversation

    service, ordinary = runtime.service, runtime.service.relationships
    if ordinary is None or ordinary.authority_resolver is None:
        raise MessagingConfigError("messaging_relationship_composition_rejected")
    if not runtime.egress.release_enabled and runtime.egress.catalog_mode != "migrate":
        raise MessagingConfigError("messaging_visibility_required")
    if application["relationship_mode"] != {
        "mode": "shared",
        "runtime_id": service.runtime_id,
        "state_root": str(runtime.state_root),
        "store_filename": ordinary.store.path.name,
    }:
        raise MessagingConfigError("messaging_relationship_composition_rejected")
    if ordinary.store.path != runtime.state_root / ordinary.store.path.name:
        raise MessagingConfigError("messaging_relationship_composition_rejected")
    identity = _identity(runtime)
    approved_by_being: dict[str, Any] = {}
    for document in application["authorities"]:
        approved = authority_from_document(document)
        if approved.manifest.being_ref in approved_by_being:
            raise MessagingConfigError("messaging_relationship_authority_mismatch")
        approved_by_being[approved.manifest.being_ref] = approved
        verified = ordinary.authority_resolver(approved.manifest.being_ref)
        active = (
            verified.active if isinstance(verified, RootHistoryAuthority) else verified
        )
        if active != approved:
            raise MessagingConfigError("messaging_relationship_authority_mismatch")
    if identity["being_ref"] not in approved_by_being:
        raise MessagingConfigError("messaging_relationship_authority_mismatch")
    retained = {canonical_bytes(event) for event in ordinary.store.events()}
    if any(
        canonical_bytes(event) not in retained
        for event in application["relationship_events"]
    ):
        raise MessagingConfigError("messaging_shared_history_incomplete")
    secrets = {}
    for row in [application["client"], *application_routes(application)]:
        key = protected_read(root / row["secret_file"], size=32)
        if hashlib.sha256(key).hexdigest() != row["secret_sha256"]:
            raise MessagingConfigError("messaging_key_rejected")
        secrets[row["secret_file"]] = key
    client = application["client"]
    capability = LocalCapability.from_value(
        client["descriptor"], secrets[client["secret_file"]]
    )
    if (
        set(capability.methods) != MESSAGING_METHODS
        or not capability.active_at(service.clock())
        or capability.capability_id in service.capabilities
        or any(
            other.client_id == capability.client_id
            for other in service.capabilities.values()
        )
    ):
        raise MessagingConfigError("messaging_capability_state_rejected")
    expected_client = {
        "schema": "dm.local.client-config/v3",
        "capability": capability.descriptor,
        "expected_server": dict(service.origin),
        "runtime_id": service.runtime_id,
        "runtime_label": service.runtime_label,
    }
    if read_document((metadata_root or root) / "client.json") != expected_client:
        raise MessagingConfigError("messaging_capability_state_rejected")
    read_capability_state(
        runtime,
        capability.descriptor
        if capability_predecessor is None
        else capability_predecessor,
    )
    stores = {
        name: _store_path(root, filename)
        for name, filename in application["stores"].items()
    }
    if not initialize and any(
        not path.is_file() or path.stat().st_size == 0 for path in stores.values()
    ):
        raise MessagingConfigError("messaging_required_store_missing")
    if not initialize:
        for name, path in stores.items():
            _validate_store_schema(
                name,
                path,
                allow_missing_visibility=runtime.egress.catalog_mode == "migrate",
            )
    # The shared relationships were validated by their base loader; use the
    # existing strict published-layout validator before this group can release.
    _validate_store_schema("relationships", ordinary.store.path)
    records = TribeRecordStore(
        stores["records"],
        sign=lambda value: create_binding(runtime, value),
        verify=lambda value, binding: verify_record_binding(runtime, value, binding),
        clock=service.clock,
    )
    lane = TribeConversation(
        service.ledger,
        signer=service.signer,
        custody=runtime.create_delivery_custody(),
        clock=service.clock,
        relationships=ordinary.store,
        card_verifier=ordinary.card_verifier,
        authority_resolver=ordinary.store.authority_resolver
        or ordinary.authority_resolver,
        records=records,
        envelopes=EnvelopeStore(stores["envelopes"]),
    )
    communication = service.communication
    if (
        communication is None
        or not communication.receipts_v2
        or not communication.legs_v3
    ):
        raise MessagingConfigError("messaging_semantic_migration_required")
    communication.foreign_authority_resolver = lane.authority_resolver
    providers = {}
    for row in application["roster"]:
        verified = lane._active(row["being_ref"])
        if not any(
            member["status"] == "active"
            and member["embodiment_id"] == row["embodiment_id"]
            and member["body_ref"] == row["body_ref"]
            for member in verified.manifest.value["embodiments"]
        ):
            raise MessagingConfigError("messaging_roster_binding_rejected")
        route = row["route"]
        providers[(row["being_ref"], row["embodiment_id"])] = {
            phase: DirectHTTPProvider(
                **{key: route[key] for key in ("provider_ref", "route_ref", "key_ref")},
                endpoint=route["endpoint"].removesuffix("message") + phase,
                secret=secrets[route["secret_file"]],
                route_class="direct",
                sender_principal=identity["being_ref"],
                sender_body_ref=service.origin["body_ref"],
                clock=service.clock,
                egress=runtime.egress,
                timeout_seconds=2,
                response_timeout_seconds=10,
                total_timeout_seconds=12,
            )
            for phase in ("message", "evidence")
        }
    labels = service.labels
    if labels is not None:
        labels = labels._with_verified_entries(
            [
                {
                    "being_ref": being_ref,
                    "body_ref": member["body_ref"],
                    "embodiment_id": member["embodiment_id"],
                }
                for being_ref, authority in approved_by_being.items()
                for member in authority.manifest.value["embodiments"]
                if member["status"] == "active"
            ]
        )
    controllers = [
        selected
        for selected in service.capabilities.values()
        if selected.client_id
        == f"client:host:{service.runtime_label}:receiving-controller"
        and set(selected.methods) == RECEIVING_CONTROL_METHODS
    ]
    if len(controllers) > 1:
        raise MessagingConfigError("messaging_reader_controller_binding_rejected")
    group = GroupMessaging(
        lane=lane,
        policy=MessagingTribePolicy(**application["tribe"]["policy"]),
        communication=communication,
        providers=providers,
        config_digest=config_digest(
            {key: value for key, value in application.items() if key != "client"}
        ),
        egress=runtime.egress,
        labels=labels,
        controlled_readers=bool(controllers),
        loaded_store_bindings=tuple(service.loaded_stores.values())
        + tuple(LoadedStoreBinding.capture(path) for path in stores.values())
        if not initialize
        else (),
    )
    group.validate(service)
    ingresses = {}
    route = application["intake"]
    for phase in ("message", "evidence"):
        ingresses[phase] = TransportIngress(
            **{key: route[key] for key in ("provider_ref", "route_ref", "key_ref")},
            secret=secrets[route["secret_file"]],
            recipient_id=service.origin["embodiment_id"],
            recipient_body_ref=service.origin["body_ref"],
            recipient_embodiment_id=service.origin["embodiment_id"],
            inbox=OpaqueInbox(stores["opaque-" + phase], clock=service.clock),
            clock=service.clock,
            egress=runtime.egress,
            egress_catalog_id=f"messaging-{phase}-responses",
            egress_authority_head=service.origin["body_ref"],
            egress_authorizer=group._authorize,
            store_guard=group._verify_loaded_stores,
            intake_validator=None,
            intake_admission=group.admit_message
            if phase == "message"
            else group.admit_evidence,
            carrier_inspector=group.inspect_carrier,
        )
    group.intake_ingresses = ingresses
    channel_id = application["tribe"]["channel_id"]

    def capability_guard(selected: LocalCapability) -> None:
        if selected.capability_id != capability.capability_id:
            raise ValueError()
        read_capability_state(runtime, selected.descriptor)

    messaging = MessagingServiceContext(
        channels={channel_id: group},
        deliveries={channel_id: group},
        client_channels={capability.client_id: frozenset({channel_id})},
        capability_guard=capability_guard,
        labels=service.labels,
    )
    return replace(
        runtime,
        service=replace(
            service,
            messaging=messaging,
            receiving=ReceivingServiceContext(
                controllers[0].capability_id, {channel_id: group}
            )
            if controllers
            else None,
            capabilities={**service.capabilities, capability.capability_id: capability},
        ),
        messaging_http=MessagingHTTPContext(
            (application["listen"]["host"], application["listen"]["port"]),
            ingresses["evidence"],
            ingresses["message"],
        ),
    )


def _read_publication(
    root: Path, verify: Callable[[Any, Any], None]
) -> tuple[Any, Path]:
    application, metadata, _ = _read_verified_publication(root, verify)
    return application, metadata


def _read_verified_publication(
    root: Path, verify: Callable[[Any, Any], None]
) -> tuple[Any, Path, Any]:
    """Read one atomic signed publication; missing pointer never means bootstrap."""
    publication = read_document(root / "publication.json")
    metadata = _publication_metadata(root, publication, verify)
    application = read_document(metadata / "application.json")
    validate_shape(application)
    verify(application, read_document(metadata / "binding.json"))
    if config_digest(application) != publication["body"]["application_sha256"]:
        raise MessagingConfigError("messaging_publication_rejected")
    return application, metadata, publication


def _publication_metadata(
    root: Path, publication: Any, verify: Callable[[Any, Any], None]
) -> Path:
    import re

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
    verify(body, publication["binding"])
    return root if generation == "." else _directory(root / generation)


def read_publication(runtime: HostedRuntime, root: Path) -> tuple[Any, Path]:
    return _read_publication(
        root, lambda value, binding: verify_binding(runtime, value, binding)
    )


@dataclass(frozen=True)
class VerifiedPublication:
    """Exact owner-verified bytes handed from visibility to application load."""

    root: Path
    metadata: Path
    application: bytes
    publication: bytes
    identity_sha256: str


def read_verified_publication(
    runtime: HostedRuntime, root: Path
) -> VerifiedPublication:
    root = _directory(root)
    application, metadata, publication = _read_verified_publication(
        root, lambda value, binding: verify_binding(runtime, value, binding)
    )
    return VerifiedPublication(
        root,
        metadata,
        canonical_bytes(application),
        canonical_bytes(publication),
        config_digest(_identity(runtime)),
    )


def read_application_authorities(
    state_root: Path | str, bundle_name: str, app_directory: Path | str, *, at_ms: int
) -> dict[str, RootAuthority]:
    """Host-only preflight BEFORE load_runtime, under the same runtime lock.

    Reads public data only. Verifies signed app/publication against the trusted
    local bundle's verified public authority. Pass the result as load_runtime's
    relationship_authorities, preserve all hooks, then call load_application
    before readiness. Neither this reader nor application loading ingests grants.
    This is not enrollment, a custody reader, or a historical-root subscription.
    """
    from .operator_rebirth import (
        AUTHORITY_SCHEMA,
        authority_from_document,
        authority_from_runtime_bundle,
    )
    from .runtime import _read_bundle, _safe_file

    try:
        root = _directory(state_root)
        bundle = _read_bundle(_safe_file(root, bundle_name, must_exist=True))
        local = authority_from_runtime_bundle(bundle)
        identity = _public_identity(
            local,
            bundle["local_origin"],
            bundle["runtime_id"],
            bundle["runtime_label"],
            at_ms,
        )
        signing = local.credentials[identity["credential_id"]]["body"]["signing_key"]
        public = unb64url(signing["public"], length=32)
        app_root = _directory(app_directory)
        if app_root == root or root in app_root.parents:
            raise ValueError()
        app, _ = _read_publication(
            app_root,
            lambda value, binding: _verify_public_binding(
                identity, public, value, binding
            ),
        )
        relationships = bundle["relationships"]
        if relationships is None or app.get("relationship_mode") != {
            "mode": "shared",
            "runtime_id": identity["runtime_id"],
            "state_root": str(root),
            "store_filename": relationships["store_filename"],
        }:
            raise MessagingConfigError("messaging_relationship_composition_rejected")
        authorities = {}
        for document in app["authorities"]:
            authority = authority_from_document(document)
            ref = authority.manifest.being_ref
            if ref in authorities:
                raise ValueError()
            authorities[ref] = authority
        if authorities.get(local.manifest.being_ref) != local:
            raise MessagingConfigError("messaging_relationship_authority_mismatch")
        # Preflight before ordinary load_runtime can initialize an existing DB.
        path = _store_path(root, relationships["store_filename"])
        if not path.is_file():
            raise MessagingConfigError("messaging_required_store_missing")
        _validate_store_schema("relationships", path)
        # Local epochs remain owned by the runtime bundle, never replaced by
        # the app's active public snapshot.
        del authorities[local.manifest.being_ref]
        # The runtime already verifies these histories. Do not replace them with
        # an application's active snapshot (or compare a snapshot to its wrapper).
        for known in bundle["sources"]["known_beings"] if bundle["sources"] else []:
            ref = known["manifest"]["being_ref"]
            if ref in authorities:
                active = authority_from_document(
                    {
                        "schema": AUTHORITY_SCHEMA,
                        **{
                            key: known[key]
                            for key in (
                                "control_artifacts",
                                "control_head",
                                "manifest",
                                "credentials",
                                "incarnations",
                            )
                        },
                    }
                )
                if active != authorities[ref]:
                    raise MessagingConfigError(
                        "messaging_relationship_authority_mismatch"
                    )
                del authorities[ref]
        return authorities
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_application_rejected") from None


def _transport_config_digest(application: Mapping[str, Any]) -> str:
    # Client lease renewal does not change transport replay bindings.
    return config_digest(
        {
            **{key: value for key, value in application.items() if key != "client"},
            "schema": APPLICATION_SCHEMA,
        }
    )


def _verify_historical_transport(
    runtime: HostedRuntime,
    root: Path,
    application: Mapping[str, Any],
    retained_digest: str,
) -> None:
    """Prove retained configuration evidence, not historical transmission authority."""
    import re

    from .operator_rebirth import authority_from_document

    current, _ = read_publication(runtime, root)
    if canonical_bytes(current) != canonical_bytes(application):
        raise MessagingConfigError("messaging_transport_conflict")
    history = runtime.service.ledger.authority
    if not isinstance(history, RootHistoryAuthority):
        raise MessagingConfigError("messaging_transport_conflict")
    being_ref = history.manifest.being_ref
    local = next(
        document
        for document in application["authorities"]
        if document["manifest"]["being_ref"] == being_ref
    )
    metadata_roots = [root]
    metadata_roots.extend(
        _directory(candidate)
        for candidate in root.iterdir()
        if re.fullmatch(r"generation-[0-9a-f]{32}", candidate.name)
    )
    for metadata in metadata_roots:
        if not (metadata / "application.json").exists():
            continue
        previous = read_document(metadata / "application.json")
        if _transport_config_digest(previous) != retained_digest:
            continue
        validate_shape(previous)
        if previous["schema"] != application["schema"]:
            raise MessagingConfigError("messaging_transport_conflict")
        binding = read_document(metadata / "binding.json")
        verify_binding_within_history(runtime, previous, binding)
        epoch = history.select(binding["body"])
        restored = {**previous, "authorities": list(previous["authorities"])}
        changed = 0
        for index, document in enumerate(previous["authorities"]):
            if document["manifest"]["being_ref"] == being_ref:
                previous_authority = authority_from_document(document)
                # The runtime can retain additional unused credential/history
                # artifacts. Every artifact supplied by this signed application
                # must nevertheless be identical to its accepted epoch.
                if (
                    previous_authority.manifest != epoch.manifest
                    or previous_authority.state != epoch.state
                    or any(
                        epoch.credentials.get(key) != value
                        for key, value in previous_authority.credentials.items()
                    )
                    or any(
                        epoch.incarnations.get(key) != value
                        for key, value in previous_authority.incarnations.items()
                    )
                ):
                    raise MessagingConfigError("messaging_transport_conflict")
                restored["authorities"][index] = local
                changed += 1
        if changed != 1 or _transport_config_digest(
            restored
        ) != _transport_config_digest(application):
            raise MessagingConfigError("messaging_transport_conflict")
        return
    raise MessagingConfigError("messaging_transport_conflict")


def _selected_store_files(application: Mapping[str, Any]) -> dict[str, str]:
    """Exclude the reserved local relationship leaf for a shared runtime."""
    return {
        name: filename
        for name, filename in application["stores"].items()
        if application.get("relationship_mode") is None or name != "relationships"
    }


def load_application(
    runtime: HostedRuntime,
    app_directory: Path | str,
    *,
    verified_publication: VerifiedPublication | None = None,
) -> HostedRuntime:
    """Load signed owner-local state; no signing, enrollment or network activity."""
    try:
        root = _directory(app_directory)
        if root == runtime.state_root or runtime.state_root in root.parents:
            raise ValueError()
        selected = verified_publication or read_verified_publication(runtime, root)
        if selected.root != root or selected.identity_sha256 != config_digest(
            _identity(runtime)
        ):
            raise MessagingConfigError("messaging_publication_owner_changed")
        application = json.loads(selected.application)
        for binding in runtime.service.loaded_stores.values():
            binding.verify()
        # A private Python hand-off never bypasses signed artifact validation.
        packet = json.loads(selected.publication)
        if selected.metadata != _publication_metadata(
            root, packet, lambda value, binding: verify_binding(runtime, value, binding)
        ):
            raise MessagingConfigError("messaging_publication_rejected")
        validate_shape(application)
        if config_digest(application) != packet["body"]["application_sha256"]:
            raise MessagingConfigError("messaging_publication_rejected")
        from .service import LoadedStoreBinding

        paths = {
            role: _store_path(root, filename)
            for role, filename in _selected_store_files(application).items()
        }
        before = {
            role: LoadedStoreBinding.file_identity(path) for role, path in paths.items()
        }
        view = _compose(runtime, root, application, metadata_root=selected.metadata)
        stores = {
            role: LoadedStoreBinding.capture(
                path,
                metadata={"relationships": "metadata"}
                if role == "relationships"
                else None,
            )
            for role, path in paths.items()
        }
        if any(stores[role].identity != before[role] for role in stores):
            raise MessagingConfigError("messaging_loaded_store_replaced")
        bindings = {
            **runtime.service.loaded_stores,
            **{"application." + role: binding for role, binding in stores.items()},
        }
        shared = {
            "ledger": LoadedStoreBinding.capture(
                runtime.service.ledger.path,
                metadata={"ledger": "metadata", "communication": "communication_meta"},
            )
        }
        if (
            application.get("relationship_mode") is not None
            and runtime.service.relationships is not None
        ):
            shared["relationships"] = LoadedStoreBinding.capture(
                runtime.service.relationships.store.path,
                metadata={"relationships": "metadata"},
            )
        # Composition may migrate layouts, but cannot adopt a different physical
        # base store under the immutable observation of the original process.
        for role, original in runtime.service.loaded_stores.items():
            original.verify()
            if role in shared and shared[role].identity != original.identity:
                raise MessagingConfigError("messaging_loaded_store_replaced")
        bindings.update(shared)
        for binding in bindings.values():
            binding.verify()
        if runtime.service.loaded_runtime is None:
            # Bare synthetic/legacy services retain absent base qualification.
            return replace(view, service=replace(view.service, loaded_stores=bindings))
        visibility = view.egress.observe_loaded_binding()
        authorities = None
        if application["schema"] == APPLICATION_SCHEMA_V3:
            from .messaging import GroupMessaging

            messaging = view.service.messaging
            if messaging is None:
                raise MessagingConfigError("messaging_group_composition_rejected")
            loaded_group = messaging.channels[application["tribe"]["channel_id"]]
            if not isinstance(loaded_group, GroupMessaging):
                raise MessagingConfigError("messaging_group_composition_rejected")
            authorities = {}
            for approved in application["authorities"]:
                ref = approved["manifest"]["being_ref"]
                verified = loaded_group.lane.authority_resolver(ref)
                if not isinstance(verified, (RootAuthority, RootHistoryAuthority)):
                    raise MessagingConfigError(
                        "messaging_relationship_authority_mismatch"
                    )
                active = (
                    verified.active
                    if isinstance(verified, RootHistoryAuthority)
                    else verified
                )
                if active.manifest.digest != config_digest(approved["manifest"]):
                    raise MessagingConfigError(
                        "messaging_relationship_authority_mismatch"
                    )
                authorities[ref] = {
                    "active_manifest_hash": active.manifest.digest,
                    "active_control_head": active.state.head,
                    "accepted_manifest_hashes": list(
                        verified.accepted_manifest_hashes
                        if isinstance(verified, RootHistoryAuthority)
                        else (active.manifest.digest,)
                    ),
                }
        document = {
            "schema": "dm.runtime.loaded-application/v1",
            "loaded_base_sha256": hashlib.sha256(
                runtime.service.loaded_runtime
            ).hexdigest(),
            "application_sha256": config_digest(application),
            "config_sha256": config_digest(
                {key: value for key, value in application.items() if key != "client"}
            ),
            "publication": packet["body"],
            "publication_sha256": config_digest(packet),
            "stores": {
                role: json.loads(binding.observation)
                for role, binding in stores.items()
            },
            "shared_stores": {
                role: json.loads(binding.observation)
                for role, binding in shared.items()
            },
            "shared_relationships": application.get("relationship_mode") is not None,
            "communication_store_role": "ledger",
            "tribe": application.get("tribe"),
            "visibility": visibility,
            "authorities": authorities,
        }
        document["loaded_view_sha256"] = config_digest(document)
        if view.service.receiving is not None:
            import time

            document["reader_gates"] = {
                channel_id: {
                    key: value
                    for key, value in group.egress.reader_snapshot(
                        channel_id, deadline_ns=time.monotonic_ns() + 2_000_000_000
                    ).items()
                    if key
                    in {
                        "process_id",
                        "process_instance_id",
                        "channel_id",
                        "context_sha256",
                        "controlled",
                    }
                }
                for channel_id, group in view.service.receiving.channels.items()
            }
        else:
            document["reader_gates"] = None
        return replace(
            view,
            service=replace(
                view.service,
                loaded_application=canonical_bytes(document),
                loaded_stores=bindings,
            ),
        )
    except MessagingConfigError:
        raise
    except Exception:
        raise MessagingConfigError("messaging_application_rejected") from None
