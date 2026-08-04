"""Authenticated, rollback-aware custody storage for DM-021 ceremonies."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .canonical import CanonicalError, b64url, canonical_bytes, unb64url

PasswordReader = Callable[[], bytes | bytearray]

SCRYPT_N: Final = 2**14
SCRYPT_R: Final = 8
SCRYPT_P: Final = 1


class KeystoreError(ValueError):
    """Raised when custody storage cannot be safely opened or changed."""


class KeystoreRollbackError(KeystoreError):
    """Raised when encrypted state is older than a trusted high-water."""


class KeystoreConflictError(KeystoreError):
    """Raised when another writer advanced the custody state."""


@dataclass(frozen=True)
class KeystoreContents:
    counter: int
    control_head: str
    secrets: Mapping[str, bytes]


def _password(reader: PasswordReader) -> bytes:
    supplied = reader()
    if not isinstance(supplied, (bytes, bytearray)):
        raise KeystoreError("password callback must return bytes")
    if len(supplied) < 12:
        raise KeystoreError("password must contain at least 12 bytes")
    result = bytes(supplied)
    if isinstance(supplied, bytearray):
        supplied[:] = b"\x00" * len(supplied)
    return result


def _assert_owner_directory(path: Path) -> None:
    if path.is_symlink():
        raise KeystoreError("keystore parent must not be a symlink")
    try:
        info = path.stat()
    except FileNotFoundError as error:
        raise KeystoreError("keystore parent does not exist") from error
    if not stat.S_ISDIR(info.st_mode):
        raise KeystoreError("keystore parent is not a directory")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise KeystoreError("keystore parent must be owner-only")


def _assert_regular_owner_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise KeystoreError("keystore file does not exist") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise KeystoreError("keystore must be a non-symlink regular file")
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise KeystoreError("keystore file must be owner-only")
    return info


def _read_secure(path: Path) -> bytes:
    before = _assert_regular_owner_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise KeystoreError("keystore changed while opening")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > 16 * 1024 * 1024:
                raise KeystoreError("keystore exceeds the 16 MiB limit")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, data: bytes) -> None:
    _assert_owner_directory(path.parent)
    temporary = path.parent / f".{path.name}.tmp-{secrets.token_hex(12)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _highwater_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.highwater")


def _read_highwater(path: Path) -> int:
    highwater = _highwater_path(path)
    if highwater.is_symlink():
        raise KeystoreError("rollback high-water must not be a symlink")
    if not highwater.exists():
        return 0
    raw = _read_secure(highwater)
    try:
        value = int(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise KeystoreError("invalid local rollback high-water") from error
    if value < 1:
        raise KeystoreError("invalid local rollback high-water")
    return value


def _write_highwater(path: Path, counter: int) -> None:
    current = _read_highwater(path)
    if counter < current:
        raise KeystoreRollbackError("refusing to lower local rollback high-water")
    _atomic_write(_highwater_path(path), str(counter).encode("ascii"))


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    _assert_owner_directory(path.parent)
    lock_path = path.with_name(f".{path.name}.lock")
    if lock_path.is_symlink():
        raise KeystoreError("keystore lock must not be a symlink")
    if lock_path.exists():
        _assert_regular_owner_file(lock_path)
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _derive(password: bytes, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    if (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise KeystoreError("keystore KDF parameters do not match V1")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KeystoreError("keystore contains a duplicate object key")
        result[key] = value
    return result


def _strict_json(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_object)


def _encrypt(
    contents: KeystoreContents, password: bytes, *, salt: bytes | None = None
) -> bytes:
    actual_salt = salt if salt is not None else secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    header: dict[str, Any] = {
        "aead": {"name": "AES-256-GCM", "nonce": b64url(nonce)},
        "counter": contents.counter,
        "kdf": {
            "n": SCRYPT_N,
            "name": "scrypt",
            "p": SCRYPT_P,
            "r": SCRYPT_R,
            "salt": b64url(actual_salt),
        },
        "schema": "dm.keystore/v1",
    }
    payload = {
        "control_head": contents.control_head,
        "schema": "dm.keystore.payload/v1",
        "secrets": {
            name: b64url(value) for name, value in sorted(contents.secrets.items())
        },
    }
    key = _derive(
        password,
        actual_salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    ciphertext = AESGCM(key).encrypt(
        nonce, canonical_bytes(payload), canonical_bytes(header)
    )
    document = dict(header)
    document["ciphertext"] = b64url(ciphertext)
    return canonical_bytes(document) + b"\n"


def _decrypt(raw: bytes, password: bytes) -> KeystoreContents:
    try:
        document = _strict_json(raw)
        if not isinstance(document, dict):
            raise KeystoreError("keystore document must be an object")
        if set(document) != {"aead", "ciphertext", "counter", "kdf", "schema"}:
            raise KeystoreError("keystore document fields mismatch")
        if document["schema"] != "dm.keystore/v1":
            raise KeystoreError("unsupported keystore version")
        if set(document["kdf"]) != {"n", "name", "p", "r", "salt"}:
            raise KeystoreError("keystore KDF fields mismatch")
        if document["kdf"]["name"] != "scrypt":
            raise KeystoreError("unsupported keystore KDF")
        if set(document["aead"]) != {"name", "nonce"}:
            raise KeystoreError("keystore AEAD fields mismatch")
        if document["aead"]["name"] != "AES-256-GCM":
            raise KeystoreError("unsupported keystore AEAD")
        counter = document["counter"]
        if not isinstance(counter, int) or isinstance(counter, bool) or counter < 1:
            raise KeystoreError("invalid keystore counter")
        header = dict(document)
        ciphertext = unb64url(header.pop("ciphertext"))
        kdf = document["kdf"]
        key = _derive(
            password,
            unb64url(kdf["salt"], length=16),
            n=kdf["n"],
            r=kdf["r"],
            p=kdf["p"],
        )
        plaintext = AESGCM(key).decrypt(
            unb64url(document["aead"]["nonce"], length=12),
            ciphertext,
            canonical_bytes(header),
        )
        payload = _strict_json(plaintext)
        if set(payload) != {"control_head", "schema", "secrets"}:
            raise KeystoreError("keystore payload fields mismatch")
        if payload["schema"] != "dm.keystore.payload/v1":
            raise KeystoreError("keystore payload version mismatch")
        if not isinstance(payload["control_head"], str) or not isinstance(
            payload["secrets"], dict
        ):
            raise KeystoreError("invalid keystore payload")
        decoded = {
            name: unb64url(value)
            for name, value in payload["secrets"].items()
            if isinstance(name, str) and isinstance(value, str)
        }
        if len(decoded) != len(payload["secrets"]):
            raise KeystoreError("invalid secret record")
        return KeystoreContents(counter, payload["control_head"], decoded)
    except InvalidTag as error:
        raise KeystoreError(
            "password or authenticated ciphertext is invalid"
        ) from error
    except (
        CanonicalError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        TypeError,
    ) as error:
        raise KeystoreError("malformed keystore") from error


class EncryptedKeystore:
    """Owner-only encrypted file with atomic writes and explicit high-waters."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))

    @classmethod
    def create(
        cls,
        path: Path,
        password_reader: PasswordReader,
        *,
        control_head: str,
        secrets: Mapping[str, bytes],
    ) -> EncryptedKeystore:
        if path.exists() or path.is_symlink():
            raise KeystoreConflictError("keystore target already exists")
        store = cls(path)
        password = _password(password_reader)
        with _exclusive(store.path):
            if store.path.exists() or store.path.is_symlink():
                raise KeystoreConflictError("keystore target already exists")
            _atomic_write(
                store.path,
                _encrypt(KeystoreContents(1, control_head, dict(secrets)), password),
            )
            _write_highwater(store.path, 1)
        return store

    def open(
        self,
        password_reader: PasswordReader,
        *,
        minimum_counter: int = 0,
        required_control_head: str | None = None,
    ) -> KeystoreContents:
        _assert_owner_directory(self.path.parent)
        contents = _decrypt(_read_secure(self.path), _password(password_reader))
        trusted_counter = max(minimum_counter, _read_highwater(self.path))
        if contents.counter < trusted_counter:
            raise KeystoreRollbackError(
                "encrypted keystore is below the trusted high-water"
            )
        if (
            required_control_head is not None
            and contents.control_head != required_control_head
        ):
            raise KeystoreRollbackError("keystore control head is stale or divergent")
        _write_highwater(self.path, contents.counter)
        return contents

    def rotate(
        self,
        current_password_reader: PasswordReader,
        replacement_password_reader: PasswordReader,
        *,
        expected_counter: int,
        control_head: str,
        secrets: Mapping[str, bytes] | None = None,
    ) -> KeystoreContents:
        with _exclusive(self.path):
            current = self.open(current_password_reader)
            if current.counter != expected_counter:
                raise KeystoreConflictError("keystore changed before rotation")
            replacement = KeystoreContents(
                counter=current.counter + 1,
                control_head=control_head,
                secrets=dict(current.secrets if secrets is None else secrets),
            )
            _atomic_write(
                self.path, _encrypt(replacement, _password(replacement_password_reader))
            )
            _write_highwater(self.path, replacement.counter)
            return replacement

    def backup(
        self,
        destination: Path,
        password_reader: PasswordReader,
        *,
        minimum_counter: int = 0,
    ) -> None:
        self.open(password_reader, minimum_counter=minimum_counter)
        if destination.exists() or destination.is_symlink():
            raise KeystoreConflictError("backup destination already exists")
        _atomic_write(Path(os.path.abspath(destination)), _read_secure(self.path))

    @classmethod
    def restore(
        cls,
        backup: Path,
        destination: Path,
        password_reader: PasswordReader,
        *,
        public_counter: int,
        public_control_head: str,
    ) -> EncryptedKeystore:
        if destination.exists() or destination.is_symlink():
            raise KeystoreConflictError("restore destination already exists")
        raw = _read_secure(Path(os.path.abspath(backup)))
        contents = _decrypt(raw, _password(password_reader))
        if contents.counter < public_counter:
            raise KeystoreRollbackError("backup is older than the public counter")
        if contents.control_head != public_control_head:
            raise KeystoreRollbackError("backup does not match the public control head")
        store = cls(destination)
        with _exclusive(store.path):
            _atomic_write(store.path, raw)
            _write_highwater(store.path, contents.counter)
        return store


__all__ = [
    "EncryptedKeystore",
    "KeystoreConflictError",
    "KeystoreContents",
    "KeystoreError",
    "KeystoreRollbackError",
    "PasswordReader",
]
