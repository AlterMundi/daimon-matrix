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

    def test_compact_multipart_publication_has_no_telegram_reply_reference(self):
        self.policy["representation"] = "compact-text/v1"
        self.test_complete_multipart_publication_required()
        record = self.worker.require_confirmed("portable-operation", self.admit())
        self.assertEqual(self.publisher.calls, len(record["parts"]))
        self.assertTrue(all(len(part["attempts"]) == 1 for part in record["parts"]))

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

    def test_explicit_late_reconciliation_reads_exact_proof_without_publication(self):
        digest = self.admit()
        retained = []
        send = self.publisher.send

        def lose(request):
            retained.append(send(request))
            raise TimeoutError("lost result after commit")

        with patch.object(self.publisher, "send", side_effect=lose):
            self.worker.advance("portable-operation", digest)
        self.worker._clock = lambda: 4102444800000
        with (
            patch.object(
                self.publisher, "send", side_effect=AssertionError("no resend")
            ),
            patch.object(
                self.publisher,
                "inspect_publication",
                return_value=retained[0],
                create=True,
            ) as reader,
        ):
            state = self.worker.reconcile_publication("portable-operation", digest)
            self.assertEqual(state["state"], "confirmed")
            self.worker.reconcile_publication("portable-operation", digest)
            self.assertEqual(reader.call_count, 1)
        record = self.journal._load("portable-operation", digest)
        self.assertEqual(record["binding"]["publication_not_after_ms"], 4102444800000)
        self.assertTrue(
            self.worker.observed_at_or_after(
                "portable-operation",
                digest,
                4102444800000,
            )
        )
        self.assertEqual(self.publisher.calls, 1)

    def test_late_multipart_proof_does_not_publish_its_missing_remainder(self):
        self.policy["representation"] = "compact-text/v1"
        self.source = projection("0123456789😀" * 800)
        digest = self.admit()
        retained = []
        send = self.publisher.send

        def lose(request):
            retained.append(send(request))
            raise TimeoutError("lost first part result")

        with patch.object(self.publisher, "send", side_effect=lose):
            self.worker.advance("portable-operation", digest)
        self.worker._clock = lambda: 4102444800000
        with (
            patch.object(self.publisher, "send", side_effect=AssertionError("no send")),
            patch.object(
                self.publisher,
                "inspect_publication",
                return_value=retained[0],
                create=True,
            ),
        ):
            state = self.worker.reconcile_publication("portable-operation", digest)
            self.assertEqual(state["state"], "queued")
            self.assertEqual(state["confirmed_parts"], 1)
            self.assertGreater(state["part_count"], 1)
            with self.assertRaisesRegex(echo.EchoError, "echo_publication_expired"):
                self.worker.advance("portable-operation", digest)
        self.assertEqual(self.publisher.calls, 1)
        self.assertEqual(self.publisher.confirmations, [])

    def test_exact_owner_proof_read_has_its_own_bound_after_expiry(self):
        import uuid

        transport = echo.ConversationJournalTransport(Path("/fixture/owner.sock"))
        identifier = str(uuid.uuid4())
        with (
            patch.object(
                transport, "_exchange", return_value={"proof": "retained"}
            ) as read,
            patch.object(echo.time, "monotonic_ns", return_value=1000),
        ):
            self.assertEqual(
                transport.inspect_publication(
                    {"publication_id": identifier, "not_after_ms": 1}
                ),
                b'{"proof":"retained"}',
            )
            read.assert_called_once_with(
                "matrix publication inspect " + identifier,
                5_000_001_000,
            )

    def test_explicit_completion_only_sends_never_attempted_remaining_parts(self):
        self.policy["representation"] = "compact-text/v1"
        self.source = projection("Exact original " + "a" * 4500 + "😀" * 16)
        digest = self.admit()
        self.worker.advance("portable-operation", digest)
        before = self.journal._load("portable-operation", digest)
        self.assertGreater(len(before["parts"]), 1)
        first = echo._copy(before["parts"][0])
        self.worker._clock = lambda: 4102444800000
        control = dict(
            schema="dm.visibility.publication-completion/v1",
            recovery_id="00000000-0000-4000-8000-000000000001",
            issued_at_ms=4102444800000,
            expires_at_ms=4102444860000,
        )
        with patch.object(
            self.publisher,
            "complete_publication",
            side_effect=lambda request, _: self.publisher.send(request),
            create=True,
        ):
            self.assertEqual(
                self.worker.complete_publication("portable-operation", digest, control)[
                    "state"
                ],
                "confirmed",
            )
            count = self.publisher.calls
            self.worker.complete_publication("portable-operation", digest, control)
        after = self.journal._load("portable-operation", digest)
        self.assertEqual(after["binding"], before["binding"])
        self.assertEqual(after["parts"][0], first)
        self.assertEqual(count, len(after["parts"]))
        self.assertEqual(self.publisher.calls, count)
        self.assertTrue(all(len(p["attempts"]) == 1 for p in after["parts"]))

    def test_late_reconciliation_requires_current_authority(self):
        digest = self.admit()
        self.publisher.lose_ack = True
        self.worker.advance("portable-operation", digest)
        self.worker._clock = lambda: 4102444800000
        self.worker._authorize = lambda _: False
        with patch.object(self.publisher, "inspect_publication", create=True) as reader:
            with self.assertRaisesRegex(echo.EchoError, "echo_authorization_blocked"):
                self.worker.reconcile_publication("portable-operation", digest)
            reader.assert_not_called()

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


class NativePublicationRetirementTests(unittest.TestCase):
    """Real native/echo SQLite transactions and signed publication receipts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "native.sqlite"
        self.now = 1000
        self.key = Ed25519PrivateKey.from_private_bytes(b"p" * 32)
        self.publisher = JournalPublisher(self.root / "publication.sqlite", self.key)
        self.policy = dict(
            schema="daimon-visibility-policy/v3",
            generation=1,
            origin="retirement-fixture",
            representation="plain-json/v2",
            acceptance_digest="a" * 64,
            proof_key_id="fixture-key",
            publication=dict(
                kind="conversation-journal/v1",
                surface_ref="fixture:conversation",
                audience=["fixture:human"],
                receipt_key=encoded(self.key.public_key().public_bytes_raw()),
            ),
        )
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "CREATE TABLE peer_outbox (request_id TEXT PRIMARY KEY, "
                "plan_sha256 TEXT NOT NULL, request BLOB NOT NULL, "
                "request_sha256 TEXT NOT NULL)"
            )
        self.controller = self.controller_for("synthetic")

    def controller_for(self, mode, path_id="peer-converse-request"):
        from daimon_matrix.native_egress import MandatoryEgressController

        c = MandatoryEgressController(
            policy=self.policy,
            proof_key=b"k" * 32,
            transport=self.publisher,
            clock=lambda: self.now,
            catalog_mode=mode,
        )

        def resolve(locator):
            with closing(sqlite3.connect(self.path)) as db:
                return db.execute(
                    "SELECT request FROM peer_outbox WHERE request_id=?", (locator,)
                ).fetchone()[0]

        c.register_catalog(
            catalog_id="native-retirement",
            path=self.path,
            resolve=resolve,
            authorize=lambda _: True,
        )
        c.register_path(path_id, "native-retirement")
        return c

    def admit(self, name, path_id="peer-converse-request"):
        raw = name.encode()
        with closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO peer_outbox VALUES (?,?,?,?)",
                (name, "a" * 64, raw, hashlib.sha256(raw).hexdigest()),
            )
            binding = self.controller.admit_in_transaction(
                db,
                catalog_id="native-retirement",
                path_id=path_id,
                operation_id=name,
                locator=name,
                native_bytes=raw,
                projection=projection(),
                deadline_ms=self.now + 60000,
                authority_head="fixture-head",
            )
            db.commit()
        return binding

    def records(self):
        with closing(sqlite3.connect(self.path)) as db:
            return (
                db.execute("SELECT count(*) FROM peer_outbox").fetchone()[0],
                db.execute(
                    "SELECT count(*) FROM mandatory_egress_operations"
                ).fetchone()[0],
                db.execute("SELECT count(*) FROM echo_v2_obligations").fetchone()[0],
            )

    def test_late_publication_reconciliation_never_reopens_native_release(self):
        from daimon_matrix.native_egress import NativeEgressError

        self.controller = self.controller_for("synthetic", "tribe-message-request")
        binding = self.admit("late-publication", "tribe-message-request")
        retained = []
        send = self.publisher.send

        def lose(request):
            retained.append(send(request))
            raise TimeoutError("lost commit response")

        with patch.object(self.publisher, "send", side_effect=lose):
            self.controller.advance_one(binding)
        self.now = binding.deadline_ms
        with (
            patch.object(
                self.publisher, "send", side_effect=AssertionError("no resend")
            ),
            patch.object(
                self.publisher,
                "inspect_publication",
                return_value=retained[0],
                create=True,
            ) as reader,
        ):
            self.assertEqual(
                self.controller.reconcile_publication(binding)["state"],
                "confirmed",
            )
            self.assertEqual(reader.call_count, 1)
        self.assertEqual(
            self.controller.inspect_retained(binding)["completed_releases"], 0
        )
        with self.assertRaisesRegex(NativeEgressError, "egress_authority_blocked"):
            self.controller.release(
                binding, b"late-publication", lambda _: self.fail("effect")
            )
        # A late proof is not a route around a later regressed wall clock either.
        self.now -= 1
        with self.assertRaisesRegex(NativeEgressError, "egress_authority_blocked"):
            self.controller.release(
                binding, b"late-publication", lambda _: self.fail("effect")
            )
        self.assertEqual(self.publisher.calls, 1)

    def test_capacity_reclaimed_without_losing_original_or_reopening_clock(self):
        from daimon_matrix.native_egress import (
            PUBLICATION_RETENTION_MS,
            NativeEgressError,
        )

        first = self.admit("first")
        self.assertEqual(self.controller.advance_one(first)["state"], "confirmed")
        self.now = first.deadline_ms + PUBLICATION_RETENTION_MS
        calls = self.publisher.calls
        with (
            patch("daimon_matrix.mandatory_echo.MAX_RECORDS", 1),
            patch("daimon_matrix.native_egress.MAX_RECORDS", 1),
        ):
            second = self.admit("second")
        self.assertEqual(self.records(), (2, 2, 1))
        retired = self.controller.inspect(first)
        self.assertTrue(retired["cache_retired"])
        self.assertEqual(
            self.controller.inspect_retained(first)["completed_releases"], 0
        )
        self.assertEqual(self.controller.advance_one(first), retired)
        self.assertEqual(self.publisher.calls, calls)
        self.now = 1000  # Retirement is an irreversible exact-operation fence.
        with self.assertRaisesRegex(NativeEgressError, "egress_authority_blocked"):
            self.controller.release(first, b"first", lambda _: self.fail("old effect"))
        reopened = self.controller_for("validate")
        self.assertTrue(reopened.inspect(first)["cache_retired"])
        self.assertEqual(reopened.inspect(second)["state"], "queued")

    def test_pending_and_ambiguous_stay_pinned_and_batch_is_bounded(self):
        from daimon_matrix.native_egress import PUBLICATION_RETENTION_MS

        pending = self.admit("pending")
        ambiguous = self.admit("ambiguous")
        self.publisher.lose_ack = True
        self.assertEqual(self.controller.advance_one(ambiguous)["state"], "ambiguous")
        self.publisher.lose_ack = False
        confirmed = [self.admit(name) for name in ["confirmed-1", "confirmed-2"]]
        for item in confirmed:
            self.controller.advance_one(item)
        self.now = confirmed[-1].deadline_ms + PUBLICATION_RETENTION_MS - 1
        self.assertEqual(self.controller.retire_confirmed_publications()["retired"], 0)
        self.now += 1
        self.assertEqual(
            self.controller.retire_confirmed_publications(limit=1)["retired"], 1
        )
        self.assertEqual(self.records(), (4, 4, 3))
        self.assertEqual(
            self.controller.retire_confirmed_publications(limit=1)["retired"], 1
        )
        self.assertEqual(self.records(), (4, 4, 2))
        self.assertEqual(
            self.controller.inspect_retained(ambiguous)["echo_state"], "ambiguous"
        )
        self.assertEqual(
            self.controller.inspect_retained(pending)["echo_state"], "queued"
        )

    def test_retirement_rolls_back_and_tampered_summary_is_rejected(self):
        from daimon_matrix.native_egress import (
            PUBLICATION_RETENTION_MS,
            NativeEgressError,
        )

        binding = self.admit("atomic")
        self.controller.advance_one(binding)
        self.now = binding.deadline_ms + PUBLICATION_RETENTION_MS
        original = self.controller._retired_status

        def fail_after_update(db, selected):
            if db.execute(
                "SELECT retirement_json FROM mandatory_egress_operations"
            ).fetchone()[0]:
                raise RuntimeError("fixture commit boundary")
            return original(db, selected)

        with (
            patch.object(
                self.controller, "_retired_status", side_effect=fail_after_update
            ),
            self.assertRaises(RuntimeError),
        ):
            self.controller.retire_confirmed_publications()
        self.assertEqual(self.records(), (1, 1, 1))
        self.assertEqual(self.controller.retire_confirmed_publications()["retired"], 1)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "UPDATE mandatory_egress_operations SET "
                "retirement_json=json_set(retirement_json,'$.status.confirmed_parts',3)"
            )
        with self.assertRaisesRegex(NativeEgressError, "egress_retirement_invalid"):
            self.controller.inspect_retained(binding)
        with self.assertRaises(NativeEgressError):
            self.controller_for("validate")

    def test_explicit_v1_migration_preserves_original_journal_bytes(self):
        from daimon_matrix.native_egress import (
            LEGACY_OPERATION_TABLE_SQL,
            VISIBILITY_SCHEMA_VERSION,
            NativeEgressError,
        )

        binding = self.admit("legacy")
        with closing(sqlite3.connect(self.path)) as db, db:
            before = db.execute("SELECT * FROM echo_v2_obligations").fetchall()
            columns = [
                row[1]
                for row in db.execute("PRAGMA table_info(mandatory_egress_operations)")
                if row[1] != "retirement_json"
            ]
            db.execute("DROP INDEX mandatory_egress_pending")
            db.execute(
                "ALTER TABLE mandatory_egress_operations RENAME TO old_operations"
            )
            db.execute(LEGACY_OPERATION_TABLE_SQL)
            fields = ",".join(columns)
            db.execute(
                f"INSERT INTO mandatory_egress_operations ({fields}) "
                f"SELECT {fields} FROM old_operations"
            )
            db.execute("DROP TABLE old_operations")
        with self.assertRaises(NativeEgressError):
            self.controller_for("validate")
        migration = self.controller_for("migrate")
        migration.migrate_registered_catalogs(version=VISIBILITY_SCHEMA_VERSION)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(
                db.execute("SELECT * FROM echo_v2_obligations").fetchall(), before
            )
        self.assertEqual(
            self.controller_for("validate").inspect(binding)["state"], "queued"
        )


if __name__ == "__main__":
    unittest.main()
