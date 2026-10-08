"""Recipient-bound protection for complete private context archives.

Uses the Matrix-qualified cryptography==50.0.0 implementation of RFC 9180
HPKE to wrap an ephemeral AES-256-GCM archive key. Streaming payloads retain
every original byte; no plaintext destination is published before its tag and
digest are verified. Transport keys are not Matrix identity or custody keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import tempfile
import time
import uuid
from pathlib import Path

RECIPIENT = "dm.being-transfer-recipient/v1"
SCHEMA = "dm.protected-being-archive/v1"
MAGIC = b"DM-PROTECTED-BEING\x00\x01"
MAX_HEADER = 32768
MAX_BYTES = 5 * 1024**3
DOMAIN = b"daimon-matrix/protected-being-archive/v1\x00"


class ProtectionError(ValueError):
    """Disclosure-safe refusal; never includes plaintext or key material."""


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def encoded(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decoded(value: object, size: int) -> bytes:
    try:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if len(raw) != size or encoded(raw) != value:
            raise ValueError
        return raw
    except (ValueError, TypeError) as exc:
        raise ProtectionError("invalid_protection_packet") from exc


def crypto():
    try:
        import cryptography
        from cryptography.hazmat.primitives import ciphers
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

        if cryptography.__version__ != "50.0.0":
            raise ImportError
        return (
            ciphers,
            x25519,
            Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305),
        )
    except ImportError:
        raise ProtectionError("qualified_protection_dependency_required") from None


def validate_recipient(value: object, *, check_expiry: bool = True) -> dict:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "name",
            "owner",
            "request_id",
            "expected_being_ref",
            "public_key",
            "expires_ms",
        }
        or value["schema"] != RECIPIENT
        or any(
            not isinstance(value[key], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value[key])
            for key in ("name", "owner")
        )
        or not isinstance(value["request_id"], str)
        or type(value["expires_ms"]) is not int
        or value["expires_ms"] < 0
        or (check_expiry and value["expires_ms"] <= int(time.time() * 1000))
        or (
            value["expected_being_ref"] is not None
            and (
                not isinstance(value["expected_being_ref"], str)
                or not re.fullmatch(
                    r"dm:being:v1:[A-Za-z0-9_-]{43}", value["expected_being_ref"]
                )
            )
        )
    ):
        raise ProtectionError("invalid_transfer_recipient")
    try:
        if str(uuid.UUID(value["request_id"])) != value["request_id"]:
            raise ValueError
    except ValueError:
        raise ProtectionError("invalid_transfer_recipient") from None
    decoded(value["public_key"], 32)
    return value


def fingerprint(recipient: dict) -> str:
    return hashlib.sha256(
        canonical(validate_recipient(recipient, check_expiry=False))
    ).hexdigest()


def _path(path: Path) -> Path:
    path = path.expanduser().absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ProtectionError("regular_protected_path_required")
    return path


def _owned(path: Path, *, limit: int) -> bytes:
    path = _path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > limit
        ):
            raise ProtectionError("private_protection_file_required")
        return stream.read(limit + 1)


def _publish(candidate: Path, output: Path) -> None:
    output = _path(output)
    info = output.parent.stat()
    if (
        not output.parent.is_dir()
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ProtectionError("private_protection_directory_required")
    candidate.chmod(0o600)
    with candidate.open("rb") as stream:
        os.fsync(stream.fileno())
    os.link(candidate, output, follow_symlinks=False)
    fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def seal(source: Path, output: Path, recipient: dict) -> dict:
    recipient = validate_recipient(recipient)
    ciphers, x25519, suite = crypto()
    source, output = _path(source), _path(output)
    if output.exists():
        raise ProtectionError("existing_protected_output_refused")
    if source.stat().st_size > MAX_BYTES:
        raise ProtectionError("protected_archive_resource_limit")
    with source.open("rb") as stream:
        plain_digest = hashlib.file_digest(stream, "sha256").hexdigest()
    core = dict(
        schema=SCHEMA,
        recipient=recipient,
        plaintext_bytes=source.stat().st_size,
        plaintext_sha256=plain_digest,
        nonce=encoded(secrets.token_bytes(12)),
    )
    key = secrets.token_bytes(32)
    wrapped = suite.encrypt(
        key,
        x25519.X25519PublicKey.from_public_bytes(decoded(recipient["public_key"], 32)),
        info=DOMAIN + canonical(core),
    )
    header = canonical({**core, "wrapped_key": encoded(wrapped)})
    encryptor = ciphers.Cipher(
        ciphers.algorithms.AES(key), ciphers.modes.GCM(decoded(core["nonce"], 12))
    ).encryptor()
    encryptor.authenticate_additional_data(DOMAIN + header)
    with tempfile.TemporaryDirectory(
        prefix=".protected-", dir=output.parent
    ) as temporary:
        candidate = Path(temporary) / "archive"
        hashed, count = hashlib.sha256(), 0
        with candidate.open("xb") as outgoing, source.open("rb") as incoming:
            candidate.chmod(0o600)
            outgoing.write(MAGIC + struct.pack(">I", len(header)) + header)
            while chunk := incoming.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_BYTES:
                    raise ProtectionError("protected_archive_resource_limit")
                hashed.update(chunk)
                outgoing.write(encryptor.update(chunk))
            outgoing.write(encryptor.finalize() + encryptor.tag)
        if (
            count != core["plaintext_bytes"]
            or hashed.hexdigest() != core["plaintext_sha256"]
        ):
            raise ProtectionError("source_changed_during_protection")
        _publish(candidate, output)
    return dict(
        schema=SCHEMA,
        recipient_digest=fingerprint(recipient),
        protected=True,
        plaintext_bytes=core["plaintext_bytes"],
        plaintext_sha256=core["plaintext_sha256"],
    )


def open_archive(
    source: Path, output: Path, recipient: dict, private_key_file: Path
) -> dict:
    """The caller supplies its owner-approved exact recipient, not header trust."""
    from cryptography.exceptions import InvalidTag

    recipient = validate_recipient(recipient, check_expiry=False)
    ciphers, x25519, suite = crypto()
    source, output = _path(source), _path(output)
    if output.exists():
        raise ProtectionError("existing_plaintext_output_refused")
    private = _owned(private_key_file, limit=32)
    if len(private) != 32:
        raise ProtectionError("private_protection_file_required")
    keypair = x25519.X25519PrivateKey.from_private_bytes(private)
    if keypair.public_key().public_bytes_raw() != decoded(recipient["public_key"], 32):
        raise ProtectionError("transfer_recipient_key_mismatch")
    try:
        with source.open("rb") as incoming:
            if incoming.read(len(MAGIC)) != MAGIC:
                raise ProtectionError("unsupported_protected_archive")
            length_raw = incoming.read(4)
            if len(length_raw) != 4:
                raise ProtectionError("invalid_protected_archive")
            length = struct.unpack(">I", length_raw)[0]
            if not 1 <= length <= MAX_HEADER:
                raise ProtectionError("protected_header_resource_limit")
            raw = incoming.read(length)
            header = json.loads(raw)
            if (
                not isinstance(header, dict)
                or set(header)
                != {
                    "schema",
                    "recipient",
                    "plaintext_bytes",
                    "plaintext_sha256",
                    "nonce",
                    "wrapped_key",
                }
                or canonical(header) != raw
                or header["schema"] != SCHEMA
                or header["recipient"] != recipient
                or type(header["plaintext_bytes"]) is not int
                or not 0 <= header["plaintext_bytes"] <= MAX_BYTES
                or not isinstance(header["plaintext_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", header["plaintext_sha256"])
                or source.stat().st_size
                != len(MAGIC) + 4 + length + header["plaintext_bytes"] + 16
            ):
                raise ProtectionError("invalid_protected_archive")
            core = {
                name: value for name, value in header.items() if name != "wrapped_key"
            }
            key = suite.decrypt(
                decoded(header["wrapped_key"], 80),
                keypair,
                info=DOMAIN + canonical(core),
            )
            if len(key) != 32:
                raise ProtectionError("invalid_protected_archive")
            incoming.seek(-16, os.SEEK_END)
            tag = incoming.read(16)
            incoming.seek(len(MAGIC) + 4 + length)
            decryptor = ciphers.Cipher(
                ciphers.algorithms.AES(key),
                ciphers.modes.GCM(decoded(header["nonce"], 12), tag),
            ).decryptor()
            decryptor.authenticate_additional_data(DOMAIN + raw)
            with tempfile.TemporaryDirectory(
                prefix=".opening-", dir=output.parent
            ) as temporary:
                candidate = Path(temporary) / "archive"
                remaining, hashed = header["plaintext_bytes"], hashlib.sha256()
                with candidate.open("xb") as outgoing:
                    candidate.chmod(0o600)
                    while remaining:
                        chunk = incoming.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ProtectionError("invalid_protected_archive")
                        plain = decryptor.update(chunk)
                        outgoing.write(plain)
                        hashed.update(plain)
                        remaining -= len(chunk)
                    tail = decryptor.finalize()
                    outgoing.write(tail)
                    hashed.update(tail)
                if hashed.hexdigest() != header["plaintext_sha256"]:
                    raise ProtectionError("protected_archive_digest_mismatch")
                _publish(candidate, output)
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise ProtectionError("protected_archive_authentication_failed") from None
    return dict(
        schema=SCHEMA,
        recipient_digest=fingerprint(recipient),
        authenticated=True,
        plaintext_bytes=header["plaintext_bytes"],
        plaintext_sha256=header["plaintext_sha256"],
    )
