"""Root-bound encrypted transport for direct Matrix peer protocol documents.

This is the native successor to the transitional ``tribe-weave/v1`` carrier.
It carries already-typed scope and sync documents without delegating identity,
membership, adoption, or ledger authority to a transport directory.
"""

from __future__ import annotations

import copy
import hashlib
import http.client
import json
import os
import secrets
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast
from urllib.parse import urlsplit

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
from .identity import VerificationError, key_id, verify_embodiment_credential
from .scopes import ScopeExchangeStore, ScopeResolver, serve_scope_request
from .sealed import RecipientTarget, recipient_descriptor
from .sync import SyncEngine
from .weave import EventSigner, RootAuthority, WeaveProtocolError

SCHEMA: Final = "dm.peer-envelope/v1"
PROFILE: Final = "HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+ED25519+JCS/v1"
SIGNATURE_DOMAIN: Final = b"daimon/peer-envelope/signature/v1\x00"
PAYLOAD_AAD_DOMAIN: Final = b"daimon/peer-envelope/payload-aad/v1\x00"
CEK_WRAP_DOMAIN: Final = b"daimon/peer-envelope/cek-wrap/v1\x00"
MAX_ENVELOPE_BYTES: Final = 3 * 1024 * 1024
MAX_PAYLOAD_BYTES: Final = 2 * 1024 * 1024
MAX_TTL_MS: Final = 60_000
CONTENT_TYPES: Final = frozenset(
    {
        "application/vnd.daimon.scope-request+json",
        "application/vnd.daimon.scope-response+json",
        "application/vnd.daimon.sync-request+json",
        "application/vnd.daimon.sync-delta+json",
    }
)
_SUITE: Final = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)


class PeerTransportError(ValueError):
    """One stable fail-closed error for all externally controlled failures."""

    def __init__(self) -> None:
        super().__init__("peer_transport_rejected")


class PeerTransportBusy(PeerTransportError):
    """An exact request is still owned by another unexpired worker."""


class PeerTransportConflict(PeerTransportError):
    """An immutable request identifier was reused for different bytes."""


class PeerTransportAmbiguous(PeerTransportError):
    """The remote effect may have completed before the response was lost."""


class PeerCustody(Protocol):
    def sign(self, key_id_value: str, preimage: bytes) -> bytes: ...

    def unwrap(self, key_id_value: str, combined: bytes, info: bytes) -> bytes: ...


@dataclass(frozen=True)
class OpenedPeerPayload:
    envelope_id: str
    correlation_id: str
    reply_to: str | None
    content_type: str
    issued_at_ms: int
    expires_at_ms: int
    sender: Mapping[str, str]
    recipient: Mapping[str, str]
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class PeerClaim:
    envelope_id: str
    request_sha256: str
    claim_id: str | None
    response: bytes | None


Clock = Callable[[], int]
PeerHandler = Callable[[Mapping[str, Any]], Mapping[str, Any]]
RoundTrip = Callable[[bytes], bytes]
_RESPONSE_NAMESPACE: Final = uuid.UUID("58ada7dc-a3d3-4019-8979-bd8712b59965")
_REQUEST_NAMESPACE: Final = uuid.UUID("34013d25-dd27-4a45-9cad-78a09bf661dc")


class KeystorePeerCustody:
    """Purpose-separated keys loaded once from an authenticated DM-021 store.

    Runtime password descriptors are deliberately one-shot.  The hosted loader
    opens the encrypted store once, verifies its rollback/control bindings, and
    gives this object only the exact key material needed by the peer profile.
    """

    def __init__(
        self,
        *,
        secrets: Mapping[str, bytes],
        signing_slots: Mapping[str, str],
        encryption_slots: Mapping[str, str],
    ) -> None:
        signing = dict(signing_slots)
        encryption = dict(encryption_slots)
        if any(
            not slot.startswith(("peer.signing.v1:", "runtime.signing.v1:"))
            for slot in signing.values()
        ) or any(
            not slot.startswith("peer.encryption.v1:") for slot in encryption.values()
        ):
            raise PeerTransportError()
        self._signing_secrets = self._resolve_secrets(secrets, signing)
        self._encryption_secrets = self._resolve_secrets(secrets, encryption)
        if any(
            key_id(
                "Ed25519",
                Ed25519PrivateKey.from_private_bytes(seed)
                .public_key()
                .public_bytes_raw(),
            )
            != key_id_value
            for key_id_value, seed in self._signing_secrets.items()
        ) or any(
            key_id(
                "X25519",
                X25519PrivateKey.from_private_bytes(seed)
                .public_key()
                .public_bytes_raw(),
            )
            != key_id_value
            for key_id_value, seed in self._encryption_secrets.items()
        ):
            raise PeerTransportError()

    @staticmethod
    def _resolve_secrets(
        secrets_map: Mapping[str, bytes], slots: Mapping[str, str]
    ) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for key_id_value, slot in slots.items():
            value = secrets_map.get(slot)
            if not isinstance(value, bytes) or len(value) != 32:
                raise PeerTransportError()
            result[key_id_value] = bytes(value)
        return result

    def sign(self, key_id_value: str, preimage: bytes) -> bytes:
        seed = self._signing_secrets.get(key_id_value)
        if seed is None:
            raise PeerTransportError()
        private = Ed25519PrivateKey.from_private_bytes(seed)
        if key_id("Ed25519", private.public_key().public_bytes_raw()) != key_id_value:
            raise PeerTransportError()
        return private.sign(preimage)

    def unwrap(self, key_id_value: str, combined: bytes, info: bytes) -> bytes:
        seed = self._encryption_secrets.get(key_id_value)
        if seed is None:
            raise PeerTransportError()
        private = X25519PrivateKey.from_private_bytes(seed)
        if key_id("X25519", private.public_key().public_bytes_raw()) != key_id_value:
            raise PeerTransportError()
        try:
            return _SUITE.decrypt(combined, private, info=info)
        except (InvalidTag, ValueError) as exception:
            raise PeerTransportError() from exception


def _safe_database_path(path: Path) -> Path:
    resolved = Path(os.path.abspath(path))
    parent = resolved.parent
    try:
        parent_info = parent.lstat()
    except FileNotFoundError as exception:
        raise PeerTransportError() from exception
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or stat.S_IMODE(parent_info.st_mode) & 0o077
    ):
        raise PeerTransportError()
    ancestor = parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise PeerTransportError()
        ancestor = ancestor.parent
    try:
        info = resolved.lstat()
    except FileNotFoundError:
        descriptor = os.open(
            resolved,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        return resolved
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise PeerTransportError()
    return resolved


class PeerExchangeStore:
    """Durable request ownership and byte-exact response replay."""

    def __init__(self, path: Path, *, clock: Clock) -> None:
        self.path = _safe_database_path(path)
        self.clock = clock
        with self._database() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS peer_exchanges ("
                "envelope_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN ('processing','responded')), "
                "claim_id TEXT, lease_until_ms INTEGER, response BLOB, "
                "response_sha256 TEXT)"
            )

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _safe_database_path(self.path)
        database: sqlite3.Connection | None = None
        try:
            database = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            database.row_factory = sqlite3.Row
            mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            database.execute("PRAGMA synchronous=FULL")
            if (
                str(mode).lower() != "delete"
                or database.execute("PRAGMA synchronous").fetchone()[0] != 2
            ):
                raise PeerTransportError()
            yield database
        except sqlite3.Error as exception:
            raise PeerTransportError() from exception
        finally:
            if database is not None:
                database.close()

    def begin(
        self,
        envelope_id: str,
        request_sha256: str,
        *,
        lease_ms: int = 30_000,
    ) -> PeerClaim:
        envelope_id = _uuid(envelope_id)
        if (
            len(request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in request_sha256)
            or not 1 <= lease_ms <= 60_000
        ):
            raise PeerTransportError()
        now = _uint(self.clock())
        if now > 2**53 - 1 - lease_ms:
            raise PeerTransportError()
        claim_id = str(uuid.uuid4())
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT * FROM peer_exchanges WHERE envelope_id=?", (envelope_id,)
            ).fetchone()
            if row is None:
                database.execute(
                    "INSERT INTO peer_exchanges "
                    "VALUES(?,?, 'processing', ?, ?, NULL, NULL)",
                    (envelope_id, request_sha256, claim_id, now + lease_ms),
                )
                database.commit()
                return PeerClaim(envelope_id, request_sha256, claim_id, None)
            if row["request_sha256"] != request_sha256:
                database.rollback()
                raise PeerTransportConflict()
            if row["state"] == "responded":
                stored_response = row["response"]
                stored_digest = row["response_sha256"]
                if not isinstance(stored_response, bytes) or not isinstance(
                    stored_digest, str
                ):
                    database.rollback()
                    raise PeerTransportError()
                response = bytes(stored_response)
                if hashlib.sha256(response).hexdigest() != stored_digest:
                    database.rollback()
                    raise PeerTransportError()
                database.commit()
                return PeerClaim(envelope_id, request_sha256, None, response)
            lease_until = row["lease_until_ms"]
            if (
                row["state"] != "processing"
                or not isinstance(row["claim_id"], str)
                or not isinstance(lease_until, int)
            ):
                database.rollback()
                raise PeerTransportError()
            if lease_until > now:
                database.rollback()
                raise PeerTransportBusy()
            database.execute(
                "UPDATE peer_exchanges SET claim_id=?, lease_until_ms=? "
                "WHERE envelope_id=?",
                (claim_id, now + lease_ms, envelope_id),
            )
            database.commit()
            return PeerClaim(envelope_id, request_sha256, claim_id, None)

    def finish(self, claim: PeerClaim, response: bytes) -> bytes:
        if claim.claim_id is None or claim.response is not None:
            raise PeerTransportError()
        if not response or len(response) > MAX_ENVELOPE_BYTES:
            raise PeerTransportError()
        digest = hashlib.sha256(response).hexdigest()
        now = _uint(self.clock())
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT * FROM peer_exchanges WHERE envelope_id=?",
                (claim.envelope_id,),
            ).fetchone()
            if (
                row is None
                or row["request_sha256"] != claim.request_sha256
                or row["state"] != "processing"
                or row["claim_id"] != claim.claim_id
                or not isinstance(row["lease_until_ms"], int)
                or row["lease_until_ms"] <= now
            ):
                database.rollback()
                raise PeerTransportConflict()
            database.execute(
                "UPDATE peer_exchanges SET state='responded', claim_id=NULL, "
                "lease_until_ms=NULL, response=?, response_sha256=? "
                "WHERE envelope_id=?",
                (response, digest, claim.envelope_id),
            )
            database.commit()
        return bytes(response)

    def abort(self, claim: PeerClaim) -> None:
        if claim.claim_id is None:
            return
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "DELETE FROM peer_exchanges WHERE envelope_id=? "
                "AND state='processing' AND claim_id=?",
                (claim.envelope_id, claim.claim_id),
            )
            database.commit()


class PeerOutbox:
    """Durably bind one logical peer call to one immutable encrypted request."""

    def __init__(self, path: Path) -> None:
        self.path = _safe_database_path(path)
        with self._database() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS peer_outbox ("
                "request_id TEXT PRIMARY KEY, plan_sha256 TEXT NOT NULL, "
                "request BLOB NOT NULL, request_sha256 TEXT NOT NULL)"
            )

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _safe_database_path(self.path)
        database: sqlite3.Connection | None = None
        try:
            database = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            database.row_factory = sqlite3.Row
            mode = database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            database.execute("PRAGMA synchronous=FULL")
            if (
                str(mode).lower() != "delete"
                or database.execute("PRAGMA synchronous").fetchone()[0] != 2
            ):
                raise PeerTransportError()
            yield database
        except sqlite3.Error as exception:
            raise PeerTransportError() from exception
        finally:
            if database is not None:
                database.close()

    def get_or_create(
        self,
        request_id: str,
        plan_sha256: str,
        factory: Callable[[], bytes],
    ) -> bytes:
        request_id = _uuid(request_id)
        if len(plan_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in plan_sha256
        ):
            raise PeerTransportError()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT * FROM peer_outbox WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if row is not None:
                if row["plan_sha256"] != plan_sha256:
                    database.rollback()
                    raise PeerTransportConflict()
                stored_request = row["request"]
                stored_digest = row["request_sha256"]
                if not isinstance(stored_request, bytes) or not isinstance(
                    stored_digest, str
                ):
                    database.rollback()
                    raise PeerTransportError()
                request = bytes(stored_request)
                if hashlib.sha256(request).hexdigest() != stored_digest:
                    database.rollback()
                    raise PeerTransportError()
                database.commit()
                return request
            request = factory()
            if not request or len(request) > MAX_ENVELOPE_BYTES:
                database.rollback()
                raise PeerTransportError()
            database.execute(
                "INSERT INTO peer_outbox VALUES(?,?,?,?)",
                (
                    request_id,
                    plan_sha256,
                    request,
                    hashlib.sha256(request).hexdigest(),
                ),
            )
            database.commit()
            return bytes(request)


def _closed(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PeerTransportError()
    return value


def _text(value: Any, maximum: int = 256) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise PeerTransportError()
    return value


def _uint(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 2**53 - 1
    ):
        raise PeerTransportError()
    return value


def _uuid(value: Any) -> str:
    text = _text(value, 36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exception:
        raise PeerTransportError() from exception
    if str(parsed) != text or parsed.variant != uuid.RFC_4122:
        raise PeerTransportError()
    return text


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PeerTransportError()
        result[key] = value
    return result


def _parse(raw: bytes) -> Mapping[str, Any]:
    if not raw or len(raw) > MAX_ENVELOPE_BYTES:
        raise PeerTransportError()
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, Mapping) or canonical_bytes(value) != raw:
            raise PeerTransportError()
        return value
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise PeerTransportError() from exception


def _origin_descriptor(
    authority: RootAuthority, origin: Mapping[str, Any], *, at_ms: int
) -> dict[str, str]:
    try:
        member = authority.validate_origin(origin, require_active=True)
        credential = authority.credentials[member["embodiment_credential_id"]]
        body = verify_embodiment_credential(credential, authority.state, at_ms=at_ms)
        principals = {row["principal_id"] for row in body["transport_principals"]}
        principal = _text(origin["principal_id"], 128)
        if (
            principal not in principals
            or "dm.we" not in body["purposes"]
            or body["embodiment_id"] != origin["embodiment_id"]
        ):
            raise PeerTransportError()
        return {
            "being_ref": authority.manifest.being_ref,
            "body_ref": _text(origin["body_ref"]),
            "credential_id": credential["artifact_id"],
            "embodiment_id": _text(origin["embodiment_id"]),
            "incarnation_id": _text(origin["incarnation_id"]),
            "principal_id": principal,
            "signing_kid": body["signing_key"]["key_id"],
        }
    except (KeyError, VerificationError, WeaveProtocolError) as exception:
        raise PeerTransportError() from exception


def _sender(value: Any) -> Mapping[str, str]:
    row = _closed(
        value,
        {
            "being_ref",
            "body_ref",
            "credential_id",
            "embodiment_id",
            "incarnation_id",
            "principal_id",
            "signing_kid",
        },
    )
    return cast(dict[str, str], {key: _text(item) for key, item in row.items()})


def _recipient(value: Any) -> Mapping[str, str]:
    row = _closed(
        value,
        {"being_ref", "credential_id", "embodiment_id", "encryption_kid"},
    )
    return cast(dict[str, str], {key: _text(item) for key, item in row.items()})


def _protected(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(item)
        for key, item in value.items()
        if key not in {"payload", "signature", "wrapped_cek"}
    }


def _info(protected: Mapping[str, Any], recipient: Mapping[str, Any]) -> bytes:
    return CEK_WRAP_DOMAIN + canonical_bytes(
        {"protected": protected, "recipient": recipient}
    )


def seal_peer_payload(
    payload: Mapping[str, Any],
    *,
    content_type: str,
    sender_authority: RootAuthority,
    sender_origin: Mapping[str, Any],
    recipient_target: RecipientTarget,
    custody: PeerCustody,
    issued_at_ms: int,
    expires_at_ms: int,
    correlation_id: str,
    envelope_id: str | None = None,
    reply_to: str | None = None,
) -> bytes:
    """Encrypt and sign one canonical typed document to one exact embodiment."""

    try:
        issued = _uint(issued_at_ms)
        expires = _uint(expires_at_ms)
        if expires <= issued or expires - issued > MAX_TTL_MS:
            raise PeerTransportError()
        if content_type not in CONTENT_TYPES:
            raise PeerTransportError()
        correlation = _uuid(correlation_id)
        envelope = _uuid(envelope_id or str(uuid.uuid4()))
        parent = None if reply_to is None else _uuid(reply_to)
        plaintext = canonical_bytes(payload)
        if not plaintext or len(plaintext) > MAX_PAYLOAD_BYTES:
            raise PeerTransportError()
        sender = _origin_descriptor(sender_authority, sender_origin, at_ms=issued)
        if (
            recipient_target.authority.manifest.digest
            != sender_authority.manifest.digest
            or recipient_target.authority.state.being_ref
            != sender_authority.state.being_ref
        ):
            raise PeerTransportError()
        recipient = recipient_descriptor(recipient_target, at_ms=issued)
        base: dict[str, Any] = {
            "schema": SCHEMA,
            "profile": PROFILE,
            "envelope_id": envelope,
            "correlation_id": correlation,
            "reply_to": parent,
            "content_type": content_type,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "being_ref": sender_authority.state.being_ref,
            "manifest_hash": sender_authority.manifest.digest,
            "sender": sender,
            "recipient": recipient,
        }
        protected = _protected(base)
        cek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        ciphertext = ChaCha20Poly1305(cek).encrypt(
            nonce, plaintext, PAYLOAD_AAD_DOMAIN + canonical_bytes(protected)
        )
        # Key IDs are content addresses, not public keys. Resolve the exact
        # credential again rather than treating an identifier as key material.
        credential = recipient_target.authority.credentials[
            recipient_target.credential_id
        ]
        body = verify_embodiment_credential(
            credential, recipient_target.authority.state, at_ms=issued
        )
        recipient_public = X25519PublicKey.from_public_bytes(
            unb64url(body["encryption_key"]["public"], length=32)
        )
        combined = _SUITE.encrypt(
            cek, recipient_public, info=_info(protected, recipient)
        )
        if len(combined) != 80:
            raise PeerTransportError()
        unsigned = {
            **base,
            "wrapped_cek": {
                "enc": b64url(combined[:32]),
                "ciphertext": b64url(combined[32:]),
            },
            "payload": {"nonce": b64url(nonce), "ciphertext": b64url(ciphertext)},
        }
        signature = custody.sign(
            sender["signing_kid"], SIGNATURE_DOMAIN + canonical_bytes(unsigned)
        )
        result = canonical_bytes(
            {
                **unsigned,
                "signature": {
                    "alg": "Ed25519",
                    "kid": sender["signing_kid"],
                    "role": "peer-transport",
                    "value": b64url(signature),
                },
            }
        )
        if len(result) > MAX_ENVELOPE_BYTES:
            raise PeerTransportError()
        return result
    except PeerTransportError:
        raise
    except (
        CanonicalError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        VerificationError,
    ) as exception:
        raise PeerTransportError() from exception


def open_peer_payload(
    raw: bytes,
    *,
    authority: RootAuthority,
    local_target: RecipientTarget,
    custody: PeerCustody,
    at_ms: int,
) -> OpenedPeerPayload:
    """Authenticate, authorize and decrypt one direct peer envelope."""

    try:
        observed_at = _uint(at_ms)
        value = _closed(
            _parse(raw),
            {
                "being_ref",
                "content_type",
                "correlation_id",
                "envelope_id",
                "expires_at_ms",
                "issued_at_ms",
                "manifest_hash",
                "payload",
                "profile",
                "recipient",
                "reply_to",
                "schema",
                "sender",
                "signature",
                "wrapped_cek",
            },
        )
        issued = _uint(value["issued_at_ms"])
        expires = _uint(value["expires_at_ms"])
        if (
            value["schema"] != SCHEMA
            or value["profile"] != PROFILE
            or value["being_ref"] != authority.state.being_ref
            or value["manifest_hash"] != authority.manifest.digest
            or value["content_type"] not in CONTENT_TYPES
            or not issued <= observed_at < expires
            or expires <= issued
            or expires - issued > MAX_TTL_MS
        ):
            raise PeerTransportError()
        envelope_id = _uuid(value["envelope_id"])
        correlation_id = _uuid(value["correlation_id"])
        reply_to = None if value["reply_to"] is None else _uuid(value["reply_to"])
        sender = _sender(value["sender"])
        origin = {
            field: sender[field]
            for field in ("body_ref", "embodiment_id", "incarnation_id", "principal_id")
            if field in sender
        }
        # body_ref is authority-relevant and cannot be reconstructed from an
        # embodiment ID. It is carried in the sender descriptor below.
        if "body_ref" not in sender:
            raise PeerTransportError()
        expected_sender = _origin_descriptor(authority, origin, at_ms=issued)
        if expected_sender != sender:
            raise PeerTransportError()
        recipient = _recipient(value["recipient"])
        expected_recipient = recipient_descriptor(local_target, at_ms=observed_at)
        if recipient != expected_recipient:
            raise PeerTransportError()
        signature = _closed(value["signature"], {"alg", "kid", "role", "value"})
        if (
            signature["alg"] != "Ed25519"
            or signature["kid"] != sender["signing_kid"]
            or signature["role"] != "peer-transport"
        ):
            raise PeerTransportError()
        unsigned = {
            key: copy.deepcopy(item)
            for key, item in value.items()
            if key != "signature"
        }
        sender_credential = authority.credentials[sender["credential_id"]]
        sender_body = verify_embodiment_credential(
            sender_credential, authority.state, at_ms=issued
        )
        Ed25519PublicKey.from_public_bytes(
            unb64url(sender_body["signing_key"]["public"], length=32)
        ).verify(
            unb64url(cast(str, signature["value"]), length=64),
            SIGNATURE_DOMAIN + canonical_bytes(unsigned),
        )
        protected = _protected(value)
        wrapped = _closed(value["wrapped_cek"], {"ciphertext", "enc"})
        cek = custody.unwrap(
            recipient["encryption_kid"],
            unb64url(cast(str, wrapped["enc"]), length=32)
            + unb64url(cast(str, wrapped["ciphertext"]), length=48),
            _info(protected, recipient),
        )
        payload = _closed(value["payload"], {"ciphertext", "nonce"})
        plaintext = ChaCha20Poly1305(cek).decrypt(
            unb64url(cast(str, payload["nonce"]), length=12),
            unb64url(cast(str, payload["ciphertext"])),
            PAYLOAD_AAD_DOMAIN + canonical_bytes(protected),
        )
        if not plaintext or len(plaintext) > MAX_PAYLOAD_BYTES:
            raise PeerTransportError()
        document = json.loads(plaintext, object_pairs_hook=_unique_object)
        if not isinstance(document, Mapping) or canonical_bytes(document) != plaintext:
            raise PeerTransportError()
        return OpenedPeerPayload(
            envelope_id=envelope_id,
            correlation_id=correlation_id,
            reply_to=reply_to,
            content_type=cast(str, value["content_type"]),
            issued_at_ms=issued,
            expires_at_ms=expires,
            sender=copy.deepcopy(sender),
            recipient=copy.deepcopy(recipient),
            payload=copy.deepcopy(dict(document)),
        )
    except PeerTransportError:
        raise
    except (
        CanonicalError,
        InvalidSignature,
        InvalidTag,
        KeyError,
        TypeError,
        ValueError,
        VerificationError,
        WeaveProtocolError,
    ) as exception:
        raise PeerTransportError() from exception


class PeerDispatcher:
    """Open, replay-guard, dispatch, and encrypt one native peer call."""

    def __init__(
        self,
        *,
        authority: RootAuthority,
        local_origin: Mapping[str, Any],
        local_target: RecipientTarget,
        custody: PeerCustody,
        store: PeerExchangeStore,
        handlers: Mapping[str, tuple[str, PeerHandler]],
        clock: Clock,
    ) -> None:
        self.authority = authority
        self.local_origin = copy.deepcopy(dict(local_origin))
        self.local_target = local_target
        self.custody = custody
        self.store = store
        self.handlers = dict(handlers)
        self.clock = clock
        request_types = {
            "application/vnd.daimon.scope-request+json",
            "application/vnd.daimon.sync-request+json",
        }
        response_types = {
            "application/vnd.daimon.scope-response+json",
            "application/vnd.daimon.sync-delta+json",
        }
        if (
            not self.handlers
            or not set(self.handlers) <= request_types
            or any(
                response not in response_types for response, _ in self.handlers.values()
            )
        ):
            raise PeerTransportError()
        _origin_descriptor(authority, self.local_origin, at_ms=_uint(clock()))
        if local_target.authority.manifest.digest != authority.manifest.digest:
            raise PeerTransportError()

    def dispatch(self, raw: bytes) -> bytes:
        opened = open_peer_payload(
            raw,
            authority=self.authority,
            local_target=self.local_target,
            custody=self.custody,
            at_ms=_uint(self.clock()),
        )
        if opened.reply_to is not None:
            raise PeerTransportError()
        configured = self.handlers.get(opened.content_type)
        if configured is None:
            raise PeerTransportError()
        response_type, handler = configured
        request_hash = hashlib.sha256(raw).hexdigest()
        claim = self.store.begin(opened.envelope_id, request_hash)
        if claim.response is not None:
            return claim.response
        try:
            response_payload = handler(opened.payload)
            now = _uint(self.clock())
            if now >= opened.expires_at_ms:
                raise PeerTransportError()
            response = seal_peer_payload(
                response_payload,
                content_type=response_type,
                sender_authority=self.authority,
                sender_origin=self.local_origin,
                recipient_target=RecipientTarget(
                    self.authority, opened.sender["credential_id"]
                ),
                custody=self.custody,
                issued_at_ms=now,
                expires_at_ms=opened.expires_at_ms,
                envelope_id=str(
                    uuid.uuid5(_RESPONSE_NAMESPACE, f"response:{opened.envelope_id}")
                ),
                correlation_id=opened.correlation_id,
                reply_to=opened.envelope_id,
            )
            return self.store.finish(claim, response)
        except Exception:
            self.store.abort(claim)
            raise


class PeerClient:
    """Prepare stable encrypted requests and validate exact encrypted replies."""

    def __init__(
        self,
        *,
        authority: RootAuthority,
        local_origin: Mapping[str, Any],
        local_target: RecipientTarget,
        custody: PeerCustody,
        outbox: PeerOutbox,
        round_trip: RoundTrip,
        clock: Clock,
    ) -> None:
        self.authority = authority
        self.local_origin = copy.deepcopy(dict(local_origin))
        self.local_target = local_target
        self.custody = custody
        self.outbox = outbox
        self.round_trip = round_trip
        self.clock = clock
        _origin_descriptor(authority, self.local_origin, at_ms=_uint(clock()))
        if local_target.authority.manifest.digest != authority.manifest.digest:
            raise PeerTransportError()

    def call(
        self,
        payload: Mapping[str, Any],
        *,
        recipient_target: RecipientTarget,
        request_content_type: str,
        response_content_type: str,
        correlation_id: str,
        deadline_ms: int,
    ) -> Mapping[str, Any]:
        correlation_id = _uuid(correlation_id)
        deadline = _uint(deadline_ms)
        now = _uint(self.clock())
        if (
            request_content_type
            not in {
                "application/vnd.daimon.scope-request+json",
                "application/vnd.daimon.sync-request+json",
            }
            or response_content_type
            not in {
                "application/vnd.daimon.scope-response+json",
                "application/vnd.daimon.sync-delta+json",
            }
            or not now < deadline <= now + MAX_TTL_MS
        ):
            raise PeerTransportError()
        envelope_id = str(
            uuid.uuid5(
                _REQUEST_NAMESPACE,
                f"{correlation_id}:{recipient_target.credential_id}",
            )
        )
        plan = {
            "schema": "dm.peer-call-plan/v1",
            "being_ref": self.authority.state.being_ref,
            "manifest_hash": self.authority.manifest.digest,
            "correlation_id": correlation_id,
            "envelope_id": envelope_id,
            "deadline_ms": deadline,
            "request_content_type": request_content_type,
            "response_content_type": response_content_type,
            "sender": self.local_origin,
            "recipient_credential_id": recipient_target.credential_id,
            "payload": copy.deepcopy(dict(payload)),
        }
        plan_hash = hashlib.sha256(canonical_bytes(plan)).hexdigest()
        raw_request = self.outbox.get_or_create(
            envelope_id,
            plan_hash,
            lambda: seal_peer_payload(
                payload,
                content_type=request_content_type,
                sender_authority=self.authority,
                sender_origin=self.local_origin,
                recipient_target=recipient_target,
                custody=self.custody,
                issued_at_ms=now,
                expires_at_ms=deadline,
                correlation_id=correlation_id,
                envelope_id=envelope_id,
            ),
        )
        try:
            raw_response = self.round_trip(raw_request)
        except PeerTransportError:
            raise
        except (ConnectionError, OSError, TimeoutError) as exception:
            raise PeerTransportAmbiguous() from exception
        response = open_peer_payload(
            raw_response,
            authority=self.authority,
            local_target=self.local_target,
            custody=self.custody,
            at_ms=_uint(self.clock()),
        )
        expected_recipient = recipient_descriptor(recipient_target, at_ms=now)
        if (
            response.content_type != response_content_type
            or response.correlation_id != correlation_id
            or response.reply_to != envelope_id
            or response.sender["credential_id"] != expected_recipient["credential_id"]
            or response.sender["embodiment_id"] != expected_recipient["embodiment_id"]
        ):
            raise PeerTransportError()
        return copy.deepcopy(dict(response.payload))


@dataclass(frozen=True)
class PeerClientContext:
    """Verified local custody and outbox used to construct one endpoint client."""

    authority: RootAuthority
    local_origin: Mapping[str, Any]
    local_target: RecipientTarget
    custody: PeerCustody
    outbox: PeerOutbox
    clock: Clock

    def target(self, embodiment_id: str) -> RecipientTarget:
        embodiment_id = _text(embodiment_id)
        rows = [
            row
            for row in self.authority.manifest.value["embodiments"]
            if row["embodiment_id"] == embodiment_id and row["status"] == "active"
        ]
        if len(rows) != 1:
            raise PeerTransportError()
        return RecipientTarget(
            self.authority, cast(str, rows[0]["embodiment_credential_id"])
        )

    def client(self, round_trip: RoundTrip) -> PeerClient:
        return PeerClient(
            authority=self.authority,
            local_origin=self.local_origin,
            local_target=self.local_target,
            custody=self.custody,
            outbox=self.outbox,
            round_trip=round_trip,
            clock=self.clock,
        )


def http_peer_round_trip(url: str, *, timeout_seconds: float) -> RoundTrip:
    """Create a bounded direct HTTP(S) carrier for one trusted endpoint."""

    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exception:
        raise PeerTransportError() from exception
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/dm-peer/v1"
        or isinstance(timeout_seconds, bool)
        or not 0 < timeout_seconds <= 30
    ):
        raise PeerTransportError()
    host = parsed.hostname

    def round_trip(raw: bytes) -> bytes:
        connection_class: type[http.client.HTTPConnection]
        if parsed.scheme == "https":
            connection_class = http.client.HTTPSConnection
        else:
            connection_class = http.client.HTTPConnection
        connection = connection_class(host, port, timeout=timeout_seconds)
        try:
            connection.request(
                "POST",
                "/dm-peer/v1",
                body=raw,
                headers={"Content-Type": "application/vnd.daimon.peer+jcs"},
            )
            response = connection.getresponse()
            body = response.read(MAX_ENVELOPE_BYTES + 1)
            if response.status == 503:
                raise PeerTransportAmbiguous()
            lengths = response.headers.get_all("Content-Length", failobj=[])
            try:
                declared = int(lengths[0]) if len(lengths) == 1 else -1
            except ValueError:
                declared = -1
            if (
                response.status != 200
                or response.headers.get("Content-Type")
                != "application/vnd.daimon.peer+jcs"
                or not 1 <= len(body) <= MAX_ENVELOPE_BYTES
                or declared != len(body)
            ):
                raise PeerTransportError()
            return body
        except PeerTransportError:
            raise
        except (http.client.HTTPException, OSError, TimeoutError) as exception:
            raise PeerTransportAmbiguous() from exception
        finally:
            connection.close()

    return round_trip


def protocol_handlers(
    *,
    resolver: ScopeResolver,
    signer: EventSigner,
    scope_store: ScopeExchangeStore,
    sync_engine: SyncEngine,
) -> dict[str, tuple[str, PeerHandler]]:
    """Bind native transport only to the existing scope and sync authorities."""

    def serve_scope(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return serve_scope_request(resolver, signer, scope_store, payload)

    def serve_sync(payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return sync_engine.serve(payload)

    return {
        "application/vnd.daimon.scope-request+json": (
            "application/vnd.daimon.scope-response+json",
            serve_scope,
        ),
        "application/vnd.daimon.sync-request+json": (
            "application/vnd.daimon.sync-delta+json",
            serve_sync,
        ),
    }


__all__ = [
    "CONTENT_TYPES",
    "MAX_ENVELOPE_BYTES",
    "KeystorePeerCustody",
    "OpenedPeerPayload",
    "PeerClaim",
    "PeerClient",
    "PeerClientContext",
    "PeerCustody",
    "PeerDispatcher",
    "PeerExchangeStore",
    "PeerOutbox",
    "PeerTransportAmbiguous",
    "PeerTransportBusy",
    "PeerTransportConflict",
    "PeerTransportError",
    "http_peer_round_trip",
    "open_peer_payload",
    "protocol_handlers",
    "seal_peer_payload",
]
