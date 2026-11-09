"""Portable publication proofs against a real, bounded SQLite fixture journal."""

import base64
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

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
        self.confirmations = []
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

    def confirm_publications(self, values):
        self.confirmations.extend(values)


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
        digest = self.journal.admit(
            "portable-operation",
            self.source,
            self.policy,
            publication_not_after_ms=4102444800000,
        )
        self.db.commit()
        return digest

    def test_audience_utf8_budget_matches_backend_request_bound(self):
        self.policy["publication"]["audience"] = [
            f"human:{i:03d}:" + "😀" * 80 for i in range(128)
        ]
        # Each name fits the character limit, but their combined UTF-8 bytes
        # exceed the shared backend budget.
        with self.assertRaises(echo.EchoError):
            echo.validate_policy(self.policy)

    def test_original_deadline_is_bound_and_expiry_never_sends(self):
        digest = self.admit()
        record = self.journal._load("portable-operation", digest)
        request = echo._record_request(record, 0)
        self.assertEqual(request["not_after_ms"], 4102444800000)
        self.worker._clock = lambda: 4102444800000
        with self.assertRaisesRegex(echo.EchoError, "echo_publication_expired"):
            self.worker.advance("portable-operation", digest)
        self.assertEqual(self.publisher.calls, 0)
        self.assertEqual(self.publisher.confirmations, [])
        # Changing an admitted operation's deadline conflicts with its digest.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(echo.EchoError):
                self.journal.admit(
                    "portable-operation",
                    self.source,
                    self.policy,
                    publication_not_after_ms=4102444800001,
                )
        finally:
            self.db.rollback()

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
        self.assertEqual(len(self.publisher.confirmations), 1)
        self.assertEqual(
            self.publisher.confirmations[0]["request_sha256"], echo._hash(request)
        )

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
        self.assertEqual(self.publisher.confirmations, [])
        with closing(sqlite3.connect(self.publisher.path)) as db, db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM publications").fetchone()[0], 1
            )

    def test_lost_response_recovers_by_exact_read_without_another_publication(self):
        digest = self.admit()
        retained = []
        send = self.publisher.send

        def lose(request):
            retained.append(send(request))
            raise TimeoutError("lost result after committed publication")

        with (
            patch.object(self.publisher, "send", side_effect=lose),
            patch.object(
                self.publisher,
                "inspect_publication",
                side_effect=lambda _: retained[0],
                create=True,
            ) as reader,
        ):
            self.assertEqual(
                self.worker.advance("portable-operation", digest)["state"], "confirmed"
            )
            self.assertEqual(reader.call_count, 1)
        self.assertEqual(self.publisher.calls, 1)
        record = self.journal._load("portable-operation", digest)
        self.assertEqual(
            record["parts"][0]["attempts"][0]["response_source"], "retained-publication"
        )
        self.assertEqual(len(self.publisher.confirmations), 1)

    def test_failed_inspection_is_reserved_once_and_remains_unknown_after_restart(self):
        digest = self.admit()
        self.publisher.lose_ack = True
        with patch.object(
            self.publisher,
            "inspect_publication",
            return_value=b'{"unsigned":true}',
            create=True,
        ) as reader:
            self.assertEqual(
                self.worker.advance("portable-operation", digest)["state"], "ambiguous"
            )
            reopened = echo.MandatoryEcho(
                self.journal,
                transport=self.publisher,
                resolve=lambda _: self.source,
                authorize=lambda _: True,
            )
            self.assertEqual(
                reopened.advance("portable-operation", digest)["state"], "ambiguous"
            )
            self.assertEqual(reader.call_count, 1)
        self.assertEqual(self.publisher.calls, 1)
        self.assertEqual(self.publisher.confirmations, [])

    def test_restart_after_lost_response_can_read_retained_proof_without_sending(self):
        digest = self.admit()
        retained = []
        send = self.publisher.send

        def lose(request):
            retained.append(send(request))
            raise TimeoutError("lost result")

        with patch.object(self.publisher, "send", side_effect=lose):
            self.assertEqual(
                self.worker.advance("portable-operation", digest)["state"], "ambiguous"
            )
        reopened = echo.MandatoryEcho(
            self.journal,
            transport=self.publisher,
            resolve=lambda _: self.source,
            authorize=lambda _: True,
        )
        with (
            patch.object(
                self.publisher,
                "send",
                side_effect=AssertionError("read recovery must not send"),
            ),
            patch.object(
                self.publisher,
                "inspect_publication",
                return_value=retained[0],
                create=True,
            ),
        ):
            self.assertEqual(
                reopened.advance("portable-operation", digest)["state"], "confirmed"
            )
        self.assertEqual(self.publisher.calls, 1)

    def test_expired_original_never_starts_a_new_inspection(self):
        digest = self.admit()
        self.publisher.lose_ack = True
        self.assertEqual(
            self.worker.advance("portable-operation", digest)["state"], "ambiguous"
        )
        self.worker._clock = lambda: 4102444800000
        with patch.object(
            self.publisher,
            "inspect_publication",
            side_effect=AssertionError("expired read"),
            create=True,
        ) as reader:
            self.assertEqual(
                self.worker.advance("portable-operation", digest)["state"], "ambiguous"
            )
            self.assertEqual(reader.call_count, 0)
        self.assertEqual(self.publisher.calls, 1)


if __name__ == "__main__":
    unittest.main()
