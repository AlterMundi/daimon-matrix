"""Root-bound recipient encryption for immutable ``dm.we.v1`` events.

The carrier sees only canonical envelope bytes.  V0 sealed-delivery vectors are
historical interoperability evidence; this module deliberately exposes only the
plural-ontology V1 profile.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url
from .communication import CommunicationError, _message_payload, _resolution_payload
from .identity import VerificationError, verify_embodiment_credential
from .keystore import EncryptedKeystore, KeystoreError, PasswordReader
from .weave import RootAuthority, WeaveProtocolError, verify_event

SCHEMA: Final = "dm.sealed-delivery/v1"
PROFILE: Final = "HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+ED25519+JCS/v1"
AUTH_SCHEMA: Final = "dm.disclosure-authorization-input/v1"
PAYLOAD_AAD_DOMAIN: Final = b"dm.sealed-delivery/payload-aad/v1\x00"
CEK_WRAP_DOMAIN: Final = b"dm.sealed-delivery/cek-wrap/v1\x00"
SIGNATURE_DOMAIN: Final = b"dm.sealed-delivery/signature/v1\x00"
MAX_ENVELOPE_BYTES: Final = 4 * 1024 * 1024
MAX_EVENT_BYTES: Final = 1024 * 1024
MAX_RECIPIENTS: Final = 256
MAX_TTL_MS: Final = 24 * 60 * 60 * 1000
_SUITE: Final = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)


class SealedDeliveryError(ValueError):
    """Stable fail-closed error; details do not reveal recipient/key state."""

    def __init__(self) -> None:
        super().__init__("sealed_delivery_rejected")


class SealedDeliveryConflict(SealedDeliveryError):
    """A request identifier was reused for different immutable input."""


@dataclass(frozen=True)
class RecipientTarget:
    """One exact root-authorized embodiment credential selected upstream."""

    authority: RootAuthority
    credential_id: str


@dataclass(frozen=True)
class DisclosureAuthorization:
    """Closed result of an upstream disclosure decision.

    DM-054 constructs this value from a signed DM-052 resolution event. DM-051
    accepts no transport roster and validates that the result matches the event,
    sender and concrete active credentials before doing cryptography.
    """

    value: Mapping[str, Any]

    @classmethod
    def synthetic(
        cls,
        *,
        event: Mapping[str, Any],
        sender: Mapping[str, Any],
        recipients: Sequence[Mapping[str, Any]],
        evidence_hash: str,
        authorized_at_ms: int,
        expires_at_ms: int,
        authorization_id: str | None = None,
    ) -> DisclosureAuthorization:
        value = {
            "schema": AUTH_SCHEMA,
            "authorization_id": authorization_id or str(uuid.uuid4()),
            "authorized_at_ms": authorized_at_ms,
            "expires_at_ms": expires_at_ms,
            "event_id": event["event_id"],
            "event_hash": event["content_hash"],
            "sensitivity": event["sensitivity"],
            "sender": copy.deepcopy(dict(sender)),
            "recipients": [copy.deepcopy(dict(item)) for item in recipients],
            "evidence_hash": evidence_hash,
        }
        _validate_authorization(value, at_ms=authorized_at_ms)
        return cls(copy.deepcopy(value))

    @classmethod
    def from_resolution_event(
        cls,
        *,
        event: Mapping[str, Any],
        resolution_event: Mapping[str, Any],
        authority: RootAuthority,
        expires_at_ms: int,
        authorization_id: str | None = None,
    ) -> DisclosureAuthorization:
        """Bind one signed same-being resolution to exact recipient credentials."""

        try:
            message = verify_event(event, authority)
            resolution = verify_event(resolution_event, authority)
            message_payload = _message_payload(message)
            intent = cast(Mapping[str, Any], message_payload["intent"])
            payload, targets = _resolution_payload(
                resolution,
                message_id=cast(str, message["event_id"]),
                scope=cast(str, intent["scope"]),
            )
        except (CommunicationError, WeaveProtocolError) as exception:
            raise _reject() from exception
        if (
            payload["scope"] not in {"/me", "/we"}
            or message_payload["reply"] is not None
            or resolution["origin"] != message["origin"]
        ):
            raise _reject()
        recipients: list[dict[str, Any]] = []
        keys: list[tuple[str, str]] = []
        for raw_target in targets:
            target = _closed(
                raw_target,
                {
                    "evidence_cursor",
                    "receipt_origin_embodiment_id",
                    "recipient_id",
                    "recipient_type",
                    "scope_kind",
                },
            )
            embodiment_id = _text(target["recipient_id"], maximum=240)
            if (
                target["scope_kind"] != "we"
                or target["recipient_type"] != "embodiment"
                or target["receipt_origin_embodiment_id"] != embodiment_id
            ):
                raise _reject()
            members = [
                row
                for row in authority.manifest.value["embodiments"]
                if row["embodiment_id"] == embodiment_id and row["status"] == "active"
            ]
            if len(members) != 1:
                raise _reject()
            descriptor = recipient_descriptor(
                RecipientTarget(
                    authority,
                    cast(str, members[0]["embodiment_credential_id"]),
                ),
                at_ms=resolution["occurred_at_ms"],
            )
            keys.append((cast(str, target["recipient_type"]), embodiment_id))
            recipients.append(descriptor)
        if keys != sorted(set(keys)):
            raise _reject()
        return cls.synthetic(
            event=message,
            sender=sender_descriptor(
                message, authority, at_ms=resolution["occurred_at_ms"]
            ),
            recipients=recipients,
            evidence_hash=resolution["content_hash"],
            authorized_at_ms=resolution["occurred_at_ms"],
            expires_at_ms=expires_at_ms,
            authorization_id=authorization_id,
        )


def _reject() -> SealedDeliveryError:
    return SealedDeliveryError()


def _closed(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _reject()
    return value


def _text(value: Any, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise _reject()
    return value


def _uint(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 2**53 - 1
    ):
        raise _reject()
    return value


def _uuid(value: Any) -> str:
    text = _text(value, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exception:
        raise _reject() from exception
    if str(parsed) != text or parsed.variant != uuid.RFC_4122:
        raise _reject()
    return text


def _hex_hash(value: Any) -> str:
    text = _text(value, maximum=64)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise _reject()
    return text


def _sender(value: Any) -> Mapping[str, Any]:
    row = _closed(
        value,
        {
            "being_ref",
            "credential_id",
            "embodiment_id",
            "incarnation_id",
            "signing_kid",
        },
    )
    _text(row["being_ref"])
    _text(row["credential_id"])
    _text(row["embodiment_id"])
    _text(row["incarnation_id"])
    _text(row["signing_kid"])
    return row


def _recipient(value: Any, *, wrapped: bool) -> Mapping[str, Any]:
    fields = {"being_ref", "credential_id", "embodiment_id", "encryption_kid"}
    if wrapped:
        fields |= {"enc", "wrapped_cek"}
    row = _closed(value, fields)
    for field in ("being_ref", "credential_id", "embodiment_id", "encryption_kid"):
        _text(row[field])
    if wrapped:
        unb64url(cast(str, row["enc"]), length=32)
        unb64url(cast(str, row["wrapped_cek"]), length=48)
    return row


def _recipient_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        cast(str, value["being_ref"]),
        cast(str, value["embodiment_id"]),
        cast(str, value["encryption_kid"]),
    )


def _reduced(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: copy.deepcopy(value[field])
        for field in ("being_ref", "credential_id", "embodiment_id", "encryption_kid")
    }


def _protected(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": envelope["schema"],
        "profile": envelope["profile"],
        "delivery_id": envelope["delivery_id"],
        "event_id": envelope["event_id"],
        "event_hash": envelope["event_hash"],
        "sensitivity": envelope["sensitivity"],
        "authorization_id": envelope["authorization_id"],
        "evidence_hash": envelope["evidence_hash"],
        "issued_at_ms": envelope["issued_at_ms"],
        "expires_at_ms": envelope["expires_at_ms"],
        "sender": copy.deepcopy(envelope["sender"]),
        "recipients": [_reduced(row) for row in envelope["recipients"]],
    }


def _hpke_info(protected: Mapping[str, Any], recipient: Mapping[str, Any]) -> bytes:
    return CEK_WRAP_DOMAIN + canonical_bytes(
        {"protected": protected, "recipient": _reduced(recipient)}
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _reject()
        value[key] = item
    return value


def _parse(raw: bytes) -> Mapping[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ENVELOPE_BYTES:
        raise _reject()
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
            raise _reject()
        return value
    except (
        CanonicalError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        TypeError,
    ) as exception:
        raise _reject() from exception


def _credential(
    target: RecipientTarget, *, at_ms: int, require_active: bool = True
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    credential = target.authority.credentials.get(target.credential_id)
    if credential is None:
        raise _reject()
    try:
        body = verify_embodiment_credential(
            credential, target.authority.state, at_ms=at_ms
        )
    except VerificationError as exception:
        raise _reject() from exception
    members = [
        row
        for row in target.authority.manifest.value["embodiments"]
        if row["embodiment_credential_id"] == target.credential_id
        and (not require_active or row["status"] == "active")
    ]
    if not members:
        raise _reject()
    return credential, body


def recipient_descriptor(target: RecipientTarget, *, at_ms: int) -> dict[str, Any]:
    credential, body = _credential(target, at_ms=at_ms)
    if "messages" not in body["purposes"]:
        raise _reject()
    return {
        "being_ref": body["being_ref"],
        "credential_id": credential["artifact_id"],
        "embodiment_id": body["embodiment_id"],
        "encryption_kid": body["encryption_key"]["key_id"],
    }


def sender_descriptor(
    event: Mapping[str, Any], authority: RootAuthority, *, at_ms: int
) -> dict[str, Any]:
    try:
        verify_event(event, authority)
        member = authority.validate_origin(event["origin"], require_active=True)
        credential = authority.credentials[member["embodiment_credential_id"]]
        body = verify_embodiment_credential(credential, authority.state, at_ms=at_ms)
    except (KeyError, VerificationError, WeaveProtocolError) as exception:
        raise _reject() from exception
    if (
        "messages" not in body["purposes"]
        or event["signature"]["kid"] != body["signing_key"]["key_id"]
    ):
        raise _reject()
    return {
        "being_ref": body["being_ref"],
        "credential_id": credential["artifact_id"],
        "embodiment_id": body["embodiment_id"],
        "incarnation_id": event["origin"]["incarnation_id"],
        "signing_kid": body["signing_key"]["key_id"],
    }


def _validate_authorization(value: Any, *, at_ms: int) -> Mapping[str, Any]:
    auth = _closed(
        value,
        {
            "schema",
            "authorization_id",
            "authorized_at_ms",
            "expires_at_ms",
            "event_id",
            "event_hash",
            "sensitivity",
            "sender",
            "recipients",
            "evidence_hash",
        },
    )
    if auth["schema"] != AUTH_SCHEMA:
        raise _reject()
    _uuid(auth["authorization_id"])
    authorized = _uint(auth["authorized_at_ms"])
    expires = _uint(auth["expires_at_ms"])
    if not authorized <= at_ms < expires or expires - authorized > MAX_TTL_MS:
        raise _reject()
    _uuid(auth["event_id"])
    _hex_hash(auth["event_hash"])
    _hex_hash(auth["evidence_hash"])
    if auth["sensitivity"] not in {"personal", "private", "shareable"}:
        raise _reject()
    _sender(auth["sender"])
    recipients = auth["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise _reject()
    for row in recipients:
        _recipient(row, wrapped=False)
    if recipients != sorted(recipients, key=_recipient_key):
        raise _reject()
    markers = {(row["being_ref"], row["embodiment_id"]) for row in recipients}
    kids = {row["encryption_kid"] for row in recipients}
    if len(markers) != len(recipients) or len(kids) != len(recipients):
        raise _reject()
    return auth


class KeystoreDeliveryCustody:
    """Purpose-specific private operations over an encrypted DM-021 keystore."""

    def __init__(
        self,
        store: EncryptedKeystore,
        password_reader: PasswordReader,
        *,
        control_head: str,
        counter: int,
        signing_slots: Mapping[str, str] | None = None,
        encryption_slots: Mapping[str, str] | None = None,
    ) -> None:
        self._store = store
        self._password_reader = password_reader
        self._control_head = control_head
        self._counter = counter
        self._signing_slots = dict(signing_slots or {})
        self._encryption_slots = dict(encryption_slots or {})
        if any(
            not slot.startswith("sealed.signing.v1:")
            for slot in self._signing_slots.values()
        ):
            raise _reject()
        if any(
            not slot.startswith("sealed.encryption.v1:")
            for slot in self._encryption_slots.values()
        ):
            raise _reject()

    def _secret(self, slots: Mapping[str, str], key_id: str) -> bytes:
        slot = slots.get(key_id)
        if slot is None:
            raise _reject()
        try:
            contents = self._store.open(
                self._password_reader,
                minimum_counter=self._counter,
                required_control_head=self._control_head,
            )
        except KeystoreError as exception:
            raise _reject() from exception
        value = contents.secrets.get(slot)
        if value is None or len(value) != 32:
            raise _reject()
        return value

    def sign(self, key_id: str, unsigned: Mapping[str, Any]) -> bytes:
        seed = self._secret(self._signing_slots, key_id)
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes_raw()
        from .identity import key_id as derive_key_id

        if derive_key_id("Ed25519", public) != key_id:
            raise _reject()
        return private.sign(SIGNATURE_DOMAIN + canonical_bytes(unsigned))

    def unwrap(self, key_id: str, combined: bytes, info: bytes) -> bytes:
        private_bytes = self._secret(self._encryption_slots, key_id)
        private = X25519PrivateKey.from_private_bytes(private_bytes)
        from .identity import key_id as derive_key_id

        if derive_key_id("X25519", private.public_key().public_bytes_raw()) != key_id:
            raise _reject()
        try:
            return _SUITE.decrypt(combined, private, info=info)
        except (InvalidTag, ValueError) as exception:
            raise _reject() from exception


def _validate_envelope(
    envelope: Mapping[str, Any],
    *,
    sender_authority: RootAuthority,
    authorization: DisclosureAuthorization,
    at_ms: int,
) -> Mapping[str, Any]:
    value = _closed(
        envelope,
        {
            "schema",
            "profile",
            "delivery_id",
            "event_id",
            "event_hash",
            "sensitivity",
            "authorization_id",
            "evidence_hash",
            "issued_at_ms",
            "expires_at_ms",
            "sender",
            "recipients",
            "payload",
            "signature",
        },
    )
    if value["schema"] != SCHEMA or value["profile"] != PROFILE:
        raise _reject()
    _uuid(value["delivery_id"])
    _uuid(value["event_id"])
    _hex_hash(value["event_hash"])
    if value["sensitivity"] not in {"personal", "private", "shareable"}:
        raise _reject()
    _uuid(value["authorization_id"])
    _hex_hash(value["evidence_hash"])
    issued = _uint(value["issued_at_ms"])
    expires = _uint(value["expires_at_ms"])
    if not issued <= at_ms < expires or expires - issued > MAX_TTL_MS:
        raise _reject()
    sender = _sender(value["sender"])
    if sender["being_ref"] != sender_authority.state.being_ref:
        raise _reject()
    target = RecipientTarget(sender_authority, cast(str, sender["credential_id"]))
    credential, body = _credential(target, at_ms=at_ms)
    if (
        body["embodiment_id"] != sender["embodiment_id"]
        or body["signing_key"]["key_id"] != sender["signing_kid"]
        or "messages" not in body["purposes"]
    ):
        raise _reject()
    members = [
        row
        for row in sender_authority.manifest.value["embodiments"]
        if row["embodiment_credential_id"] == credential["artifact_id"]
        and row["incarnation_id"] == sender["incarnation_id"]
        and row["status"] == "active"
    ]
    if len(members) != 1:
        raise _reject()
    recipients = value["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise _reject()
    for row in recipients:
        _recipient(row, wrapped=True)
    if recipients != sorted(recipients, key=_recipient_key):
        raise _reject()
    if len({(row["being_ref"], row["embodiment_id"]) for row in recipients}) != len(
        recipients
    ):
        raise _reject()
    payload = _closed(value["payload"], {"nonce", "ciphertext"})
    unb64url(cast(str, payload["nonce"]), length=12)
    ciphertext = unb64url(cast(str, payload["ciphertext"]))
    if not 16 <= len(ciphertext) <= MAX_EVENT_BYTES + 16:
        raise _reject()
    signature = _closed(value["signature"], {"alg", "kid", "role", "value"})
    if (
        signature["alg"] != "Ed25519"
        or signature["role"] != "delivery-authorization"
        or signature["kid"] != sender["signing_kid"]
    ):
        raise _reject()
    unsigned = {
        key: copy.deepcopy(item) for key, item in value.items() if key != "signature"
    }
    try:
        Ed25519PublicKey.from_public_bytes(
            unb64url(body["signing_key"]["public"], length=32)
        ).verify(
            unb64url(cast(str, signature["value"]), length=64),
            SIGNATURE_DOMAIN + canonical_bytes(unsigned),
        )
    except (CanonicalError, InvalidSignature, ValueError) as exception:
        raise _reject() from exception
    auth = _validate_authorization(authorization.value, at_ms=at_ms)
    if (
        auth["authorization_id"] != value["authorization_id"]
        or auth["event_id"] != value["event_id"]
        or auth["event_hash"] != value["event_hash"]
        or auth["sensitivity"] != value["sensitivity"]
        or auth["evidence_hash"] != value["evidence_hash"]
        or auth["sender"] != sender
        or auth["recipients"] != [_reduced(row) for row in recipients]
        or not auth["authorized_at_ms"] <= issued < auth["expires_at_ms"]
    ):
        raise _reject()
    return value


def inspect_delivery(raw: bytes, *, at_ms: int) -> dict[str, Any]:
    """Validate the carrier-visible structure without claiming recipient intake.

    A route has neither disclosure authority nor recipient private keys.  This
    parser therefore proves only canonical framing, bounded fields, expiry and
    the immutable delivery digest.  ``open_event`` remains the authoritative
    recipient-side signature, disclosure and decryption gate.
    """

    try:
        value = _closed(
            _parse(raw),
            {
                "schema",
                "profile",
                "delivery_id",
                "event_id",
                "event_hash",
                "sensitivity",
                "authorization_id",
                "evidence_hash",
                "issued_at_ms",
                "expires_at_ms",
                "sender",
                "recipients",
                "payload",
                "signature",
            },
        )
        if value["schema"] != SCHEMA or value["profile"] != PROFILE:
            raise _reject()
        _uuid(value["delivery_id"])
        _uuid(value["event_id"])
        _hex_hash(value["event_hash"])
        _uuid(value["authorization_id"])
        _hex_hash(value["evidence_hash"])
        if value["sensitivity"] not in {"personal", "private", "shareable"}:
            raise _reject()
        issued = _uint(value["issued_at_ms"])
        expires = _uint(value["expires_at_ms"])
        if not issued <= at_ms < expires or expires - issued > MAX_TTL_MS:
            raise _reject()
        sender = _sender(value["sender"])
        recipients = value["recipients"]
        if (
            not isinstance(recipients, list)
            or not 1 <= len(recipients) <= MAX_RECIPIENTS
        ):
            raise _reject()
        for row in recipients:
            _recipient(row, wrapped=True)
        if recipients != sorted(recipients, key=_recipient_key):
            raise _reject()
        if len({(row["being_ref"], row["embodiment_id"]) for row in recipients}) != len(
            recipients
        ):
            raise _reject()
        payload = _closed(value["payload"], {"nonce", "ciphertext"})
        unb64url(cast(str, payload["nonce"]), length=12)
        ciphertext = unb64url(cast(str, payload["ciphertext"]))
        if not 16 <= len(ciphertext) <= MAX_EVENT_BYTES + 16:
            raise _reject()
        signature = _closed(value["signature"], {"alg", "kid", "role", "value"})
        if (
            signature["alg"] != "Ed25519"
            or signature["role"] != "delivery-authorization"
            or signature["kid"] != sender["signing_kid"]
        ):
            raise _reject()
        unb64url(cast(str, signature["value"]), length=64)
        return {
            "schema": SCHEMA,
            "delivery_id": value["delivery_id"],
            "event_id": value["event_id"],
            "event_hash": value["event_hash"],
            "sensitivity": value["sensitivity"],
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "sender": copy.deepcopy(sender),
            "recipient_embodiment_ids": sorted(
                str(row["embodiment_id"]) for row in recipients
            ),
            "envelope_sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    except SealedDeliveryError:
        raise
    except (CanonicalError, KeyError, TypeError, ValueError) as exception:
        raise _reject() from exception


def seal_event(
    event: Mapping[str, Any],
    *,
    sender_authority: RootAuthority,
    recipients: Sequence[RecipientTarget],
    authorization: DisclosureAuthorization,
    custody: KeystoreDeliveryCustody,
    issued_at_ms: int,
    expires_at_ms: int,
) -> bytes:
    """Return one immutable canonical envelope; no transport is invoked."""

    try:
        plaintext = canonical_bytes(event)
        if len(plaintext) > MAX_EVENT_BYTES:
            raise _reject()
        sender = sender_descriptor(event, sender_authority, at_ms=issued_at_ms)
        _, sender_body = _credential(
            RecipientTarget(sender_authority, cast(str, sender["credential_id"])),
            at_ms=issued_at_ms,
        )
        recipient_rows = sorted(
            (recipient_descriptor(target, at_ms=issued_at_ms) for target in recipients),
            key=_recipient_key,
        )
        if not 1 <= len(recipient_rows) <= MAX_RECIPIENTS:
            raise _reject()
        if len(
            {(row["being_ref"], row["embodiment_id"]) for row in recipient_rows}
        ) != len(recipient_rows):
            raise _reject()
        recipient_bodies = [
            _credential(target, at_ms=issued_at_ms)[1] for target in recipients
        ]
        auth = _validate_authorization(authorization.value, at_ms=issued_at_ms)
        if (
            auth["event_id"] != event["event_id"]
            or auth["event_hash"] != event["content_hash"]
            or auth["sensitivity"] != event["sensitivity"]
            or auth["sender"] != sender
            or auth["recipients"] != recipient_rows
            or not issued_at_ms < expires_at_ms <= auth["expires_at_ms"]
            or expires_at_ms - issued_at_ms > MAX_TTL_MS
            or event["occurred_at_ms"] > issued_at_ms
            or expires_at_ms > sender_body["valid_until_ms"]
            or any(expires_at_ms > body["valid_until_ms"] for body in recipient_bodies)
        ):
            raise _reject()
        base: dict[str, Any] = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "delivery_id": str(uuid.uuid4()),
            "event_id": event["event_id"],
            "event_hash": event["content_hash"],
            "sensitivity": event["sensitivity"],
            "authorization_id": auth["authorization_id"],
            "evidence_hash": auth["evidence_hash"],
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": expires_at_ms,
            "sender": sender,
            "recipients": recipient_rows,
        }
        protected = _protected(base)
        cek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        if len(cek) != 32 or len(nonce) != 12:
            raise _reject()
        ciphertext = ChaCha20Poly1305(cek).encrypt(
            nonce, plaintext, PAYLOAD_AAD_DOMAIN + canonical_bytes(protected)
        )
        wrapped_rows: list[dict[str, Any]] = []
        for target, row in zip(
            sorted(
                recipients,
                key=lambda item: _recipient_key(
                    recipient_descriptor(item, at_ms=issued_at_ms)
                ),
            ),
            recipient_rows,
            strict=True,
        ):
            _, body = _credential(target, at_ms=issued_at_ms)
            public = X25519PublicKey.from_public_bytes(
                unb64url(body["encryption_key"]["public"], length=32)
            )
            combined = _SUITE.encrypt(cek, public, info=_hpke_info(protected, row))
            if len(combined) != 80:
                raise _reject()
            wrapped_rows.append(
                {
                    **row,
                    "enc": b64url(combined[:32]),
                    "wrapped_cek": b64url(combined[32:]),
                }
            )
        unsigned = {
            **base,
            "recipients": wrapped_rows,
            "payload": {"nonce": b64url(nonce), "ciphertext": b64url(ciphertext)},
        }
        signature = custody.sign(cast(str, sender["signing_kid"]), unsigned)
        envelope = {
            **unsigned,
            "signature": {
                "alg": "Ed25519",
                "kid": sender["signing_kid"],
                "role": "delivery-authorization",
                "value": b64url(signature),
            },
        }
        raw = canonical_bytes(envelope)
        if len(raw) > MAX_ENVELOPE_BYTES:
            raise _reject()
        _validate_envelope(
            _parse(raw),
            sender_authority=sender_authority,
            authorization=authorization,
            at_ms=issued_at_ms,
        )
        return raw
    except SealedDeliveryError:
        raise
    except (
        CanonicalError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        WeaveProtocolError,
    ) as exception:
        raise _reject() from exception


def open_event(
    raw: bytes,
    *,
    sender_authority: RootAuthority,
    local_target: RecipientTarget,
    recipient_targets: Sequence[RecipientTarget],
    authorization: DisclosureAuthorization,
    custody: KeystoreDeliveryCustody,
    at_ms: int,
) -> Mapping[str, Any]:
    """Authenticate, authorize and decrypt exactly one local recipient entry."""

    try:
        envelope = _validate_envelope(
            _parse(raw),
            sender_authority=sender_authority,
            authorization=authorization,
            at_ms=at_ms,
        )
        expected_recipients = sorted(
            (recipient_descriptor(target, at_ms=at_ms) for target in recipient_targets),
            key=_recipient_key,
        )
        if not 1 <= len(
            expected_recipients
        ) <= MAX_RECIPIENTS or expected_recipients != [
            _reduced(row) for row in envelope["recipients"]
        ]:
            raise _reject()
        local = recipient_descriptor(local_target, at_ms=at_ms)
        matches = [row for row in envelope["recipients"] if _reduced(row) == local]
        if len(matches) != 1:
            raise _reject()
        row = matches[0]
        protected = _protected(envelope)
        cek = custody.unwrap(
            cast(str, row["encryption_kid"]),
            unb64url(cast(str, row["enc"]), length=32)
            + unb64url(cast(str, row["wrapped_cek"]), length=48),
            _hpke_info(protected, row),
        )
        if len(cek) != 32:
            raise _reject()
        payload = cast(Mapping[str, Any], envelope["payload"])
        try:
            plaintext = ChaCha20Poly1305(cek).decrypt(
                unb64url(cast(str, payload["nonce"]), length=12),
                unb64url(cast(str, payload["ciphertext"])),
                PAYLOAD_AAD_DOMAIN + canonical_bytes(protected),
            )
        except (InvalidTag, ValueError) as exception:
            raise _reject() from exception
        if not plaintext or len(plaintext) > MAX_EVENT_BYTES:
            raise _reject()
        event = json.loads(plaintext, object_pairs_hook=_unique_object)
        if not isinstance(event, Mapping) or canonical_bytes(event) != plaintext:
            raise _reject()
        verified = verify_event(event, sender_authority)
        sender = envelope["sender"]
        if (
            verified["event_id"] != envelope["event_id"]
            or verified["content_hash"] != envelope["event_hash"]
            or verified["sensitivity"] != authorization.value["sensitivity"]
            or verified["occurred_at_ms"] > envelope["issued_at_ms"]
            or verified["origin"]["embodiment_id"] != sender["embodiment_id"]
            or verified["origin"]["incarnation_id"] != sender["incarnation_id"]
            or verified["being_ref"] != sender["being_ref"]
        ):
            raise _reject()
        return copy.deepcopy(dict(verified))
    except SealedDeliveryError:
        raise
    except (
        CanonicalError,
        json.JSONDecodeError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
        WeaveProtocolError,
    ) as exception:
        raise _reject() from exception


class EnvelopeStore:
    """Durable request-id to immutable ciphertext mapping (DELETE/FULL SQLite)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        self._prepare_path()
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS envelopes ("
                "request_id TEXT PRIMARY KEY, plan_hash TEXT NOT NULL, "
                "envelope BLOB NOT NULL, envelope_hash TEXT NOT NULL)"
            )
        finally:
            connection.close()

    def _prepare_path(self) -> None:
        if self.path.parent.is_symlink():
            raise _reject()
        info = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise _reject()
        ancestor = self.path.parent
        while ancestor != ancestor.parent:
            if ancestor.is_symlink():
                raise _reject()
            ancestor = ancestor.parent
        try:
            file_info = self.path.lstat()
        except FileNotFoundError:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
            return
        if (
            stat.S_ISLNK(file_info.st_mode)
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != os.geteuid()
            or stat.S_IMODE(file_info.st_mode) & 0o077
        ):
            raise _reject()

    def _connect(self) -> sqlite3.Connection:
        self._prepare_path()
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        try:
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()[0]
            if str(mode).lower() != "delete" or synchronous != 2:
                raise _reject()
            return connection
        except BaseException:
            connection.close()
            raise

    def get_or_create(
        self, request_id: str, plan_hash: str, factory: Callable[[], bytes]
    ) -> bytes:
        _uuid(request_id)
        _hex_hash(plan_hash)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT plan_hash, envelope, envelope_hash FROM envelopes "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if row[0] != plan_hash or hashlib.sha256(row[1]).hexdigest() != row[2]:
                    raise SealedDeliveryConflict()
                connection.commit()
                return cast(bytes, row[1])
            envelope = factory()
            parsed = _parse(envelope)
            if parsed["schema"] != SCHEMA:
                raise _reject()
            envelope_hash = hashlib.sha256(envelope).hexdigest()
            connection.execute(
                "INSERT INTO envelopes(request_id, plan_hash, envelope, envelope_hash) "
                "VALUES (?, ?, ?, ?)",
                (request_id, plan_hash, envelope, envelope_hash),
            )
            connection.commit()
            return envelope
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


def sealing_plan_hash(
    event: Mapping[str, Any],
    authorization: DisclosureAuthorization,
    recipients: Sequence[RecipientTarget],
    *,
    issued_at_ms: int,
    expires_at_ms: int,
) -> str:
    rows = sorted(
        (recipient_descriptor(target, at_ms=issued_at_ms) for target in recipients),
        key=_recipient_key,
    )
    plan = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "event": copy.deepcopy(dict(event)),
        "authorization": copy.deepcopy(dict(authorization.value)),
        "recipients": rows,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    return hashlib.sha256(canonical_bytes(plan)).hexdigest()


__all__ = [
    "AUTH_SCHEMA",
    "PROFILE",
    "SCHEMA",
    "DisclosureAuthorization",
    "EnvelopeStore",
    "KeystoreDeliveryCustody",
    "RecipientTarget",
    "SealedDeliveryConflict",
    "SealedDeliveryError",
    "inspect_delivery",
    "open_event",
    "recipient_descriptor",
    "seal_event",
    "sealing_plan_hash",
    "sender_descriptor",
]
