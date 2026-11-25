"""Shared disposable backend for signed Conversation publication tests."""

import hashlib
import sqlite3
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import mandatory_echo as echo
from daimon_matrix.canonical import b64url
from daimon_matrix.native_egress import (
    _private_sibling_visibility,
    _PrivateSiblingVisibility,
)


class JournalPublisher:
    def __init__(self, path: Path, key: Ed25519PrivateKey) -> None:
        self.path, self.key = path, key
        self.calls = 0
        self.change: Callable[[dict[str, Any]], None] = lambda receipt: None
        self.lose_ack = False
        self.confirmations: list[dict[str, str]] = []
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                "CREATE TABLE publications (id TEXT PRIMARY KEY, request TEXT NOT NULL)"
            )

    def send(self, request: dict[str, Any]) -> bytes:
        self.calls += 1
        raw = echo._json(request)
        # The owning backend commits before issuing its durability attestation.
        with closing(sqlite3.connect(self.path)) as db, db:
            prior = db.execute(
                "SELECT request FROM publications WHERE id=?",
                (request["publication_id"],),
            ).fetchone()
            if prior is not None and prior[0] != raw:
                raise ValueError("publication_conflict")
            db.execute(
                "INSERT OR IGNORE INTO publications VALUES (?,?)",
                (request["publication_id"], raw),
            )
        with closing(sqlite3.connect(self.path)) as db, db:
            sequence = db.execute(
                "SELECT rowid FROM publications WHERE id=?",
                (request["publication_id"],),
            ).fetchone()[0]
        if self.lose_ack:
            raise TimeoutError("fixture lost acknowledgment after commit")
        receipt: dict[str, Any] = dict(
            schema="dm.visibility.publication-receipt/v1",
            request_sha256=echo._hash(request),
            publication_id=request["publication_id"],
            surface_ref=request["surface_ref"],
            audience=request["audience"],
            text_sha256=hashlib.sha256(request["text"].encode()).hexdigest(),
            committed_at_ms=1,
            sequence=sequence,
            durable=True,
        )
        self.change(receipt)
        receipt["signature"] = b64url(self.key.sign(echo._json(receipt).encode()))
        return echo._json(receipt).encode()

    def confirm_publications(self, values: list[dict[str, str]]) -> None:
        self.confirmations.extend(values)


def private_sibling_document(
    path: Path, key: Ed25519PrivateKey, pair: tuple[str, str]
) -> dict[str, Any]:
    return {
        "schema": "dm.messaging.private-sibling-visibility/v1",
        "embodiments": sorted(pair),
        "destination": {
            "representation": "compact-text/v1",
            "publication": {
                "kind": "conversation-journal/v1",
                "surface_ref": "conversation:private-fixture",
                "audience": ["human:fixture"],
                "receipt_key": b64url(key.public_key().public_bytes_raw()),
            },
        },
        "publication_backend": {
            "kind": "owner-unix/v1",
            "socket_path": str(path.with_suffix(".sock")),
        },
    }


def private_sibling_fixture(
    path: Path, base_policy: Mapping[str, Any], pair: tuple[str, str]
) -> tuple[_PrivateSiblingVisibility, JournalPublisher]:
    key = Ed25519PrivateKey.generate()
    publication = private_sibling_document(path, key, pair)
    selection = _private_sibling_visibility(
        publication, owner_embodiment=pair[0], base_policy=base_policy
    )
    publisher = JournalPublisher(path, key)
    return replace(selection, transport=publisher), publisher
