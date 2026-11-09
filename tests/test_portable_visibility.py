"""Portable publication proofs against a real, bounded SQLite fixture journal."""

import base64
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import mandatory_echo as echo
from tests.test_mandatory_echo import projection


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class JournalPublisher:
    def __init__(self, path, key):
        self.path, self.key = path, key
        self.calls = 0
        self.change = lambda receipt: None
        self.lose_ack = False
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                "CREATE TABLE publications (id TEXT PRIMARY KEY, request TEXT NOT NULL)"
            )

    def send(self, request):
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
        receipt = dict(
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
        receipt["signature"] = encoded(self.key.sign(echo._json(receipt).encode()))
        return echo._json(receipt).encode()


class PortablePublicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.key = Ed25519PrivateKey.from_private_bytes(b"p" * 32)
        self.publisher = JournalPublisher(root / "human-journal.sqlite", self.key)
        self.db = sqlite3.connect(root / "native.sqlite", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute("BEGIN IMMEDIATE")
        echo.EchoJournal.initialize(
            self.db, catalog_id="portable-fixture", authentication_key=b"k" * 32
        )
        self.db.commit()
        self.journal = echo.EchoJournal(
            self.db, catalog_id="portable-fixture", authentication_key=b"k" * 32
        )
        self.policy = dict(
            schema="daimon-visibility-policy/v3",
            generation=1,
            origin="fixture-owner",
            representation="plain-json/v2",
            acceptance_digest="a" * 64,
            proof_key_id="fixture-proof-key",
            publication=dict(
                kind="conversation-journal/v1",
                surface_ref="fixture:general-conversation",
                audience=["fixture:paired-human"],
                receipt_key=encoded(self.key.public_key().public_bytes_raw()),
            ),
        )
        self.source = projection()
        self.worker = echo.MandatoryEcho(
            self.journal,
            transport=self.publisher,
            resolve=lambda _: self.source,
            authorize=lambda _: True,
        )

    def admit(self):
        self.db.execute("BEGIN IMMEDIATE")
        digest = self.journal.admit("portable-operation", self.source, self.policy)
        self.db.commit()
        return digest

    def test_committed_signed_publication_survives_native_journal_reopen(self):
        digest = self.admit()
        self.worker.advance("portable-operation", digest)
        self.worker.require_confirmed("portable-operation", digest)
        reopened = echo.EchoJournal(
            self.db, catalog_id="portable-fixture", authentication_key=b"k" * 32
        )
        worker = echo.MandatoryEcho(
            reopened,
            transport=None,
            resolve=lambda _: self.source,
            authorize=lambda _: True,
        )
        worker.require_confirmed("portable-operation", digest)
        with closing(sqlite3.connect(self.publisher.path)) as db, db:
            request = json.loads(
                db.execute("SELECT request FROM publications").fetchone()[0]
            )
        self.assertNotIn("chat_id", request)
        self.assertEqual(request["audience"], ["fixture:paired-human"])
        self.assertIn(self.source["content"]["text"], request["text"])
        self.assertEqual(self.publisher.calls, 1)

    def test_complete_multipart_publication_required(self):
        self.source = projection("0123456789😀" * 800)
        digest = self.admit()
        self.worker.advance("portable-operation", digest)
        with self.assertRaises(echo.EchoError):
            self.worker.require_confirmed("portable-operation", digest)
        for _ in range(32):
            if (
                self.worker.advance("portable-operation", digest)["state"]
                == "confirmed"
            ):
                break
        self.worker.require_confirmed("portable-operation", digest)
        self.assertGreater(self.publisher.calls, 1)

    def test_wrong_surface_audience_content_or_durability_never_unlocks(self):
        digest = self.admit()
        for field, wrong in [
            ("audience", ["fixture:other-human"]),
            ("surface_ref", "fixture:another-conversation"),
            ("text_sha256", "0" * 64),
            ("durable", False),
        ]:
            record = self.journal._load("portable-operation", digest)
            request = echo._record_request(record, 0)
            self.publisher.change = lambda receipt, field=field, wrong=wrong: (
                receipt.update({field: wrong})
            )
            with self.assertRaises(ValueError):
                echo._classify_response(
                    self.publisher.send(request), request, self.policy
                )

    def test_unsigned_telegram_or_wrong_key_receipts_do_not_unlock(self):
        digest = self.admit()
        request = echo._record_request(
            self.journal._load("portable-operation", digest), 0
        )
        for raw in [b'{"ok":true}', b'{"durable":true}']:
            with self.assertRaises(ValueError):
                echo._classify_response(raw, request, self.policy)
        self.publisher.key = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
        state = self.worker.advance("portable-operation", digest)
        self.assertEqual(state["state"], "ambiguous")
        with self.assertRaises(echo.EchoError):
            self.worker.require_confirmed("portable-operation", digest)

    def test_lost_ack_preserves_commit_and_does_not_retry(self):
        digest = self.admit()
        self.publisher.lose_ack = True
        self.assertEqual(
            self.worker.advance("portable-operation", digest)["state"], "ambiguous"
        )
        self.assertEqual(
            self.worker.advance("portable-operation", digest)["state"], "ambiguous"
        )
        self.assertEqual(self.publisher.calls, 1)
        with closing(sqlite3.connect(self.publisher.path)) as db, db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM publications").fetchone()[0], 1
            )


if __name__ == "__main__":
    unittest.main()
