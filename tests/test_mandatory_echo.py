"""Synthetic runtime-owned echo obligations; no credentials or Telegram traffic."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from daimon_matrix import mandatory_echo as echo


def policy():
    return {
        "schema": "daimon-visibility-policy/v2",
        "generation": 1,
        "origin": "synthetic-runtime",
        "bot_id": 123,
        "chat_id": -123,
        "topic_id": None,
        "representation": "plain-json/v2",
        "acceptance_digest": "a" * 64,
        "proof_key_id": "synthetic-proof-key",
    }


def projection(text="hello <&> 😀", event_id="synthetic-event"):
    return {
        "event_id": event_id,
        "event_digest": "b" * 64,
        "sender": "synthetic-being/alice/embodiment-a",
        "recipients": ["synthetic-being/bob/embodiment-b"],
        "thread_id": "synthetic-thread",
        "reply_to": None,
        "kind": "message",
        "content": {"text": text},
    }


class Transport:
    def __init__(self):
        self.calls = []

    def send(self, request):
        self.calls.append(request)
        result = {
            "message_id": len(self.calls),
            "from": {"id": 123, "is_bot": True},
            "chat": {"id": request["chat_id"]},
            "text": request["text"],
        }
        if "message_thread_id" in request:
            result.update(
                message_thread_id=request["message_thread_id"], is_topic_message=True
            )
        return json.dumps({"ok": True, "result": result}).encode()


class EchoTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "native-outbox.db"
        self.db = self.connect()
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE native_outbox (operation_id TEXT PRIMARY KEY)")
        self.db.execute("BEGIN IMMEDIATE")
        echo.EchoJournal.initialize(
            self.db, catalog_id="synthetic-catalog", authentication_key=b"k" * 32
        )
        self.db.commit()
        self.journal = self.reopen(self.db)
        self.transport = Transport()
        self.allowed = True
        self.source = projection()
        self.worker = self.worker_for(self.journal)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=0, isolation_level=None)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        return db

    def reopen(self, db):
        return echo.EchoJournal(
            db, catalog_id="synthetic-catalog", authentication_key=b"k" * 32
        )

    def worker_for(self, journal):
        return echo.MandatoryEcho(
            journal,
            transport=self.transport,
            resolve=lambda operation_id: self.source,
            authorize=lambda binding: self.allowed,
        )

    def admit(self, operation_id="synthetic-op"):
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO native_outbox VALUES (?)", (operation_id,))
        binding = self.journal.admit(operation_id, self.source, policy())
        self.db.commit()
        return binding

    def test_closed_policy_projection_and_control_registry(self):
        import copy

        bad_projections = []
        for field, value in (
            ("kind", "echo-status"),
            ("kind", "secret"),
            ("kind", "reply"),
            ("recipients", []),
            ("recipients", ["a", "b"]),
            ("event_digest", "bad"),
            ("event_id", ""),
            ("sender", True),
            ("content", {"text": "x", "signature": "not-for-disclosure"}),
            ("content", {"text": "x" * 65537}),
        ):
            p = projection()
            p[field] = value
            bad_projections.append(p)
        bad_projections.append({**projection(), "control": True})
        for p in bad_projections:
            with self.subTest(projection=p.get("kind")):
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    with self.assertRaisesRegex(
                        echo.EchoError, "^echo_projection_invalid$"
                    ):
                        self.journal.admit("bad-op", p, policy())
                finally:
                    self.db.rollback()
        for field, value in (
            ("schema", "v1"),
            ("generation", True),
            ("generation", 0),
            ("bot_id", True),
            ("chat_id", 0),
            ("topic_id", True),
            ("acceptance_digest", "no"),
            ("representation", "HTML"),
            ("proof_key_id", ""),
            ("origin", ""),
        ):
            p = policy()
            p[field] = value
            self.db.execute("BEGIN IMMEDIATE")
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(echo.EchoError, "^echo_policy_invalid$"),
            ):
                self.journal.admit("bad-policy", projection(), p)
            self.db.rollback()
        controls = {
            "semantic-receipt": {"outcome": "delivered"},
            "transport-result": {"stage": "message", "outcome": "accepted"},
            "authorization-control": {"stage": "evidence-before-message"},
        }
        for kind, content in controls.items():
            p = copy.deepcopy(projection())
            p.update(
                kind=kind,
                content=content,
                reply_to={"event_id": "ref", "event_digest": "c" * 64},
            )
            self.source = p
            binding = self.admit(kind)
            self.assertEqual(self.worker.advance(kind, binding)["state"], "confirmed")
        self.assertEqual(len(self.transport.calls), 3)

    def test_crash_boundaries_retain_intent_and_verified_results(self):
        class Crash(BaseException):
            pass

        binding = self.admit()
        points = []

        def checkpoint(point):
            points.append(point)
            if point == "intent_committed":
                raise Crash()

        self.worker._checkpoint = checkpoint
        with self.assertRaises(Crash):
            self.worker.advance("synthetic-op", binding)
        self.assertEqual(points, ["intent_committed"])
        self.assertEqual(len(self.transport.calls), 0)
        self.assertEqual(
            self.worker_for(self.reopen(self.db)).advance("synthetic-op", binding)[
                "state"
            ],
            "ambiguous",
        )
        self.assertEqual(len(self.transport.calls), 0)
        # A different logical operation crashes only after validated proof commit.
        self.source = projection(event_id="event-2")
        second = self.admit("op-2")

        def after_result(point):
            if point == "response_committed":
                raise Crash()

        worker = self.worker_for(self.journal)
        worker._checkpoint = after_result
        with self.assertRaises(Crash):
            worker.advance("op-2", second)
        recovered = self.worker_for(self.reopen(self.db))
        self.assertEqual(recovered.advance("op-2", second)["state"], "confirmed")
        self.assertEqual(len(self.transport.calls), 1)

    def test_noncanonical_duplicate_record_and_schema_extensions_fail_closed(self):
        binding = self.admit()
        self.worker.advance("synthetic-op", binding)
        raw = self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        duplicated = raw.replace('"revision":2', '"revision":999,"revision":2')
        self.assertNotEqual(raw, duplicated)
        self.db.execute("UPDATE echo_v2_obligations SET record=?", (duplicated,))
        with self.assertRaisesRegex(echo.EchoError, "echo_state_invalid"):
            self.worker.require_confirmed("synthetic-op", binding)
        self.db.execute("UPDATE echo_v2_obligations SET record=?", (raw,))
        self.db.execute(
            "CREATE TRIGGER echo_v2_unreviewed AFTER UPDATE "
            "ON echo_v2_obligations BEGIN SELECT 1; END"
        )
        with self.assertRaisesRegex(echo.EchoError, "echo_catalog_invalid"):
            self.reopen(self.db)

    def test_sqlite_busy_and_closed_connection_errors_are_sanitized(self):
        binding = self.admit()
        other = self.connect()
        try:
            other.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(echo.EchoError, "^echo_storage_unavailable$"):
                self.worker.advance("synthetic-op", binding)
        finally:
            other.rollback()
            other.close()
        self.assertEqual(len(self.transport.calls), 0)
        self.db.close()
        with self.assertRaisesRegex(echo.EchoError, "^echo_catalog_invalid$"):
            self.worker.inspect("synthetic-op", binding)

    def test_multipart_outage_prefix_and_ambiguity_never_replay(self):
        self.source = projection("<&😀" * 3000)
        binding = self.admit()
        offline = echo.MandatoryEcho(
            self.journal,
            transport=None,
            resolve=lambda _: self.source,
            authorize=lambda _: True,
        )
        self.assertEqual(offline.advance("synthetic-op", binding)["state"], "queued")
        first = self.worker.advance("synthetic-op", binding)
        self.assertEqual(first["state"], "queued")
        self.assertEqual(first["confirmed_parts"], 1)
        self.allowed = False
        with self.assertRaisesRegex(echo.EchoError, "echo_authorization_blocked"):
            self.worker.advance("synthetic-op", binding)
        self.assertEqual(len(self.transport.calls), 1)
        self.allowed = True
        original = self.transport.send

        def lost_response(request):
            original(request)  # actual synthetic remote acceptance, lost result
            raise OSError("TOKEN_MUST_NOT_LEAK")

        self.transport.send = lost_response
        state = self.worker.advance("synthetic-op", binding)
        self.assertEqual(state["state"], "ambiguous")
        self.assertEqual(state["confirmed_parts"], 1)
        self.assertNotIn("TOKEN", repr(state))
        self.transport.send = original
        other = self.connect()
        try:
            resumed = self.worker_for(self.reopen(other))
            for _ in range(3):
                self.assertEqual(resumed.advance("synthetic-op", binding), state)
            with self.assertRaisesRegex(echo.EchoError, "echo_not_confirmed"):
                resumed.require_confirmed("synthetic-op", binding)
        finally:
            other.close()
        self.assertEqual(len(self.transport.calls), 2)

    def test_complete_multipart_preserves_every_identity_content_and_reply(self):
        self.source = projection("https://example.org <&😀\n" * 1200)
        self.source.update(
            kind="reply",
            reply_to={"event_id": "replied-event", "event_digest": "c" * 64},
        )
        binding = self.admit()
        for _ in range(32):
            if self.worker.advance("synthetic-op", binding)["state"] == "confirmed":
                break
        proof = self.worker.require_confirmed("synthetic-op", binding)
        complete = "".join(p["text"].split("\n", 1)[1] for p in proof["parts"])
        self.assertEqual(json.loads(complete), self.source)
        self.assertEqual(len(self.transport.calls), len(proof["parts"]))
        self.assertTrue(all(len(p["attempts"]) == 1 for p in proof["parts"]))
        self.source = {**self.source, "sender": "different-sender"}
        with self.assertRaisesRegex(echo.EchoError, "echo_authorization_blocked"):
            self.worker.require_confirmed("synthetic-op", binding)

    def test_pending_status_hash_and_swapped_proofs_cannot_release(self):
        import copy

        binding = self.admit()
        pending = self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[
            0
        ]
        self.worker.advance("synthetic-op", binding)
        confirmed = self.db.execute(
            "SELECT record FROM echo_v2_obligations"
        ).fetchone()[0]
        original = json.loads(confirmed)
        altered = []
        forged = json.loads(pending)
        forged["state"] = "confirmed"
        altered.append(forged)
        for change in (
            lambda p: p["binding"]["projection"].update(sender="mallory"),
            lambda p: p["binding"]["policy"].update(chat_id=-999),
            lambda p: p["binding"]["policy"].update(topic_id=9),
            lambda p: p["binding"]["policy"].update(bot_id=999),
            lambda p: p["parts"][0].update(text="changed"),
            lambda p: p["parts"][0]["attempts"][0].update(response='{"ok":true}'),
            lambda p: p["parts"][0]["attempts"][0].update(attempt_id="changed"),
            lambda p: p.update(parts=[]),
        ):
            record = copy.deepcopy(original)
            change(record)
            record["binding_digest"] = echo._hash(record["binding"])
            altered.append(record)
        for record in altered:
            self.db.execute(
                "UPDATE echo_v2_obligations SET record=?", (echo._json(record),)
            )
            with self.assertRaisesRegex(echo.EchoError, "echo_state_invalid"):
                self.worker.require_confirmed("synthetic-op", record["binding_digest"])
        self.db.execute("UPDATE echo_v2_obligations SET record=?", (confirmed,))
        self.source = projection(event_id="event-2")
        second = self.admit("op-2")
        self.db.execute(
            "UPDATE echo_v2_obligations SET record=? WHERE operation_id='op-2'",
            (confirmed,),
        )
        with self.assertRaisesRegex(echo.EchoError, "echo_state_invalid"):
            self.worker.require_confirmed("op-2", second)
        self.assertEqual(len(self.transport.calls), 1)

    def test_admission_rollback_missing_state_and_reinitialization(self):
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO native_outbox VALUES ('rolled-back')")
        binding = self.journal.admit("rolled-back", self.source, policy())
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM native_outbox").fetchone()[0], 0
        )
        with self.assertRaisesRegex(echo.EchoError, "echo_state_missing"):
            self.worker.advance("rolled-back", binding)
        with self.assertRaisesRegex(echo.EchoError, "echo_transaction_required"):
            self.journal.admit("no-transaction", self.source, policy())
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(echo.EchoError, "echo_initialization_failed"):
            echo.EchoJournal.initialize(
                self.db, catalog_id="synthetic-catalog", authentication_key=b"k" * 32
            )
        self.db.rollback()
        binding = self.admit()
        self.db.execute("DELETE FROM echo_v2_obligations")
        with self.assertRaisesRegex(echo.EchoError, "echo_state_missing"):
            self.worker.require_confirmed("synthetic-op", binding)
        for key in (b"x" * 32, b"bad"):
            with self.assertRaises(echo.EchoError):
                echo.EchoJournal(
                    self.db, catalog_id="synthetic-catalog", authentication_key=key
                )
        self.db.execute("DROP TABLE echo_v2_obligations")
        with self.assertRaisesRegex(echo.EchoError, "echo_catalog_invalid"):
            self.reopen(self.db)
        self.assertEqual(len(self.transport.calls), 0)

    def test_competing_connections_cannot_claim_inflight_part(self):
        binding = self.admit()
        original = self.transport.send

        def competing(request):
            other = self.connect()
            try:
                # Intent is visible DURABLY and no SQL writer lock is held in HTTP.
                other.execute("BEGIN IMMEDIATE")
                other.rollback()
                rival = self.worker_for(self.reopen(other))
                self.assertEqual(
                    rival.advance("synthetic-op", binding)["state"], "ambiguous"
                )
                with self.assertRaisesRegex(echo.EchoError, "echo_not_confirmed"):
                    rival.require_confirmed("synthetic-op", binding)
            finally:
                other.close()
            return original(request)

        self.transport.send = competing
        self.assertEqual(
            self.worker.advance("synthetic-op", binding)["state"], "confirmed"
        )
        self.assertEqual(len(self.transport.calls), 1)

    def test_process_death_after_remote_result_never_blind_replays(self):
        import os
        import subprocess
        import sys

        binding = self.admit()
        child = """
import os, sqlite3, sys
from daimon_matrix import mandatory_echo as echo
from tests.test_mandatory_echo import Transport, projection
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("PRAGMA synchronous=FULL")
journal = echo.EchoJournal(conn, catalog_id="synthetic-catalog",
    authentication_key=b"k"*32)
worker = echo.MandatoryEcho(journal, transport=Transport(),
    resolve=lambda _: projection(), authorize=lambda _: True)
def stop(point):
    if point == "response_verified":
        os._exit(73)
worker._checkpoint = stop
worker.advance("synthetic-op", sys.argv[2])
"""
        result = subprocess.run(
            [sys.executable, "-c", child, str(self.path), binding],
            # Use the same artifact as the parent, even from outside the repo.
            # A literal "src" silently retested checkout code in wheel checks.
            env={
                **os.environ,
                "PYTHONPATH": os.pathsep.join(
                    [
                        str(Path(echo.__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[1]),
                    ]
                ),
            },
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 73, result.stderr.decode())
        state = self.worker.advance("synthetic-op", binding)
        self.assertEqual(state["state"], "ambiguous")
        self.assertEqual(len(self.transport.calls), 0)
        with self.assertRaisesRegex(echo.EchoError, "echo_not_confirmed"):
            self.worker.require_confirmed("synthetic-op", binding)

    def test_proof_shape_is_exact_and_never_a_signature_verifier(self):
        import copy

        binding = self.admit()
        self.worker.advance("synthetic-op", binding)
        proof = self.worker.require_confirmed("synthetic-op", binding)
        self.assertIsNone(echo.validate_proof_shape(proof))
        for change in (
            lambda p: p.update(extra=True),
            lambda p: p.update(parts=[]),
            lambda p: p.update(revision=True),
            lambda p: p["parts"][0].update(text="replacement"),
            lambda p: p["parts"][0]["attempts"].append(p["parts"][0]["attempts"][0]),
            lambda p: p["parts"][0]["attempts"][0].update(attempt_id="not-a-uuid"),
        ):
            altered = copy.deepcopy(proof)
            change(altered)
            with self.assertRaisesRegex(echo.EchoError, "^echo_proof_invalid$"):
                echo.validate_proof_shape(altered)

    def test_published_schemas_match_runtime_records(self):
        import copy

        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource

        root = Path(__file__).resolve().parents[1] / "schemas/messaging/v2"
        policy_schema = json.loads((root / "visibility-policy.schema.json").read_text())
        proof_schema = json.loads((root / "echo-proof.schema.json").read_text())
        registry = Registry().with_resource(
            policy_schema["$id"], Resource.from_contents(policy_schema)
        )
        validator = Draft202012Validator(proof_schema, registry=registry)
        Draft202012Validator.check_schema(proof_schema)
        Draft202012Validator.check_schema(policy_schema)
        Draft202012Validator(policy_schema).validate(policy())
        binding = self.admit()
        pending = json.loads(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        )
        validator.validate(pending)
        self.worker.advance("synthetic-op", binding)
        confirmed = self.worker.require_confirmed("synthetic-op", binding)
        validator.validate(confirmed)
        for key in confirmed:
            malformed = copy.deepcopy(confirmed)
            del malformed[key]
            self.assertTrue(list(validator.iter_errors(malformed)), key)
        unknown = {**confirmed, "confirmed": True}
        self.assertTrue(list(validator.iter_errors(unknown)))

    def test_capacity_fails_closed_without_eviction_or_network(self):
        from unittest.mock import patch

        binding = self.admit()
        for limit in ("MAX_RECORDS", "MAX_TOTAL_BYTES", "MAX_RECORD_BYTES"):
            self.db.execute("BEGIN IMMEDIATE")
            try:
                with (
                    patch.object(echo, limit, 1),
                    self.assertRaisesRegex(echo.EchoError, "echo_capacity"),
                ):
                    self.journal.admit("capacity-op", self.source, policy())
            finally:
                self.db.rollback()
        self.assertEqual(
            self.worker.inspect("synthetic-op", binding)["state"], "queued"
        )
        self.assertEqual(len(self.transport.calls), 0)
        # Admission is not an implicit startup migration.
        empty = sqlite3.connect(":memory:")
        try:
            with self.assertRaisesRegex(echo.EchoError, "echo_catalog_invalid"):
                self.reopen(empty)
            self.assertEqual(
                empty.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0
            )
        finally:
            empty.close()

    def test_admission_storage_error_is_sanitized_and_parent_can_rollback(self):
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("PRAGMA query_only=ON")
        try:
            with self.assertRaisesRegex(echo.EchoError, "^echo_storage_unavailable$"):
                self.journal.admit("read-only", self.source, policy())
        finally:
            self.db.rollback()
            self.db.execute("PRAGMA query_only=OFF")
        self.assertEqual(len(self.transport.calls), 0)
        self.db.close()
        with self.assertRaisesRegex(echo.EchoError, "^echo_storage_unavailable$"):
            self.worker.advance("closed-db", "a" * 64)

    def test_verified_rejection_retries_after_backoff_without_unlocking(self):
        now = [10000]
        binding = self.admit()
        original = self.transport.send

        def reject_once(request):
            self.transport.calls.append(request)
            return (
                b'{"ok":false,"error_code":429,"description":"synthetic busy",'
                b'"parameters":{"retry_after":2}}'
            )

        self.transport.send = reject_once
        worker = echo.MandatoryEcho(
            self.journal,
            transport=self.transport,
            resolve=lambda _: self.source,
            authorize=lambda _: self.allowed,
            clock=lambda: now[0],
        )
        self.assertEqual(worker.advance("synthetic-op", binding)["state"], "queued")
        with self.assertRaisesRegex(echo.EchoError, "echo_not_confirmed"):
            worker.require_confirmed("synthetic-op", binding)
        self.transport.send = original
        self.assertEqual(worker.advance("synthetic-op", binding)["state"], "queued")
        self.assertEqual(len(self.transport.calls), 1)
        now[0] += 2000
        self.assertEqual(worker.advance("synthetic-op", binding)["state"], "confirmed")
        proof = worker.require_confirmed("synthetic-op", binding)
        self.assertEqual(len(proof["parts"][0]["attempts"]), 2)
        self.assertIn('"ok":false', proof["parts"][0]["attempts"][0]["response"])
        self.assertEqual(len(self.transport.calls), 2)

    def test_http_deadline_reaps_executor_before_guard_release(self):
        import subprocess
        import threading
        import time
        from contextlib import contextmanager
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import patch

        from daimon_matrix import telegram_mirror as mirror

        binding = self.admit()
        received = threading.Event()
        waiting = threading.Event()
        released = threading.Event()
        lock = threading.Lock()
        children, results, errors, posts = [], [], [], []
        mode = ["slow"]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                request = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                posts.append(request)
                received.set()
                raw = Transport().send(request)
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    if mode[0] == "slow":
                        for byte in raw:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(0.04)
                    else:
                        self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        original_exchange, original_popen = (
            mirror._plain_http_exchange,
            subprocess.Popen,
        )

        def local_exchange(url, payload):
            self.assertEqual(
                url, "https://api.telegram.org/bot123:TEST_ONLY/sendMessage"
            )
            return original_exchange(
                f"http://127.0.0.1:{server.server_port}/sendMessage", payload
            )

        def capture(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child

        @contextmanager
        def guard():
            with lock:
                try:
                    yield
                finally:
                    self.assertTrue(all(c.poll() is not None for c in children))
                    released.set()

        def run():
            db = self.connect()
            try:
                worker = echo.MandatoryEcho(
                    self.reopen(db),
                    transport=mirror.PlainTelegramTransport(
                        token="123:TEST_ONLY", bot_id=123, chat_id=-123, topic_id=None
                    ),
                    resolve=lambda _: self.source,
                    authorize=lambda _: True,
                    execution_guard=guard,
                )
                results.append(worker.advance("synthetic-op", binding))
            except BaseException as exc:
                errors.append(exc)
            finally:
                db.close()

        def contender():
            waiting.set()
            try:
                with lock:
                    self.assertTrue(released.is_set())
                    self.assertTrue(all(c.poll() is not None for c in children))
            except BaseException as exc:
                errors.append(exc)

        try:
            with (
                patch.object(mirror, "_plain_http_exchange", local_exchange),
                patch.object(mirror, "_PLAIN_HTTP_SECONDS", 0.6),
                patch.object(subprocess, "Popen", capture),
            ):
                worker_thread = threading.Thread(target=run)
                worker_thread.start()
                self.assertTrue(received.wait(3))
                contender_thread = threading.Thread(target=contender)
                contender_thread.start()
                self.assertTrue(waiting.wait(3))
                self.assertFalse(released.is_set())
                worker_thread.join(3)
                contender_thread.join(3)
                self.assertFalse(worker_thread.is_alive())
                self.assertFalse(contender_thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(results[0]["state"], "ambiguous")
                self.assertEqual(len(posts), 1)
                self.assertEqual(children[0].returncode, -9)
                self.assertEqual(
                    self.worker.advance("synthetic-op", binding)["state"], "ambiguous"
                )
                self.assertEqual(len(posts), 1)
                # A different operation makes progress after quiescence.
                mode[0] = "success"
                second = self.admit("second")
                self.worker._transport = mirror.PlainTelegramTransport(
                    token="123:TEST_ONLY", bot_id=123, chat_id=-123, topic_id=None
                )
                self.worker._execution_guard = guard
                self.assertEqual(
                    self.worker.advance("second", second)["state"], "confirmed"
                )
                self.assertEqual(len(posts), 2)
                self.assertTrue(all(c.poll() is not None for c in children))
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_duplicate_retry_id_rejected_before_write_and_effect(self):
        import threading
        from dataclasses import asdict

        binding = self.admit()
        self.worker._clock = lambda: 1000
        original = self.transport.send

        def lost(request):
            self.transport.calls.append(request)
            raise TimeoutError()

        self.transport.send = lost
        self.worker.advance("synthetic-op", binding)
        self.worker._execution_guard = threading.Lock
        self.worker._verify_retry = lambda raw, *_: echo.RetryDecision(
            **json.loads(raw)
        )

        def command(ident):
            record = self.journal._load("synthetic-op", binding)
            return echo._json(
                asdict(
                    echo.RetryDecision(
                        ident,
                        "synthetic-owner",
                        "synthetic-op",
                        binding,
                        record["parts"][0]["attempts"][-1]["attempt_id"],
                        1000,
                        2000,
                        "duplicate-platform-post-accepted",
                    )
                )
            ).encode()

        ident = "00000000-0000-4000-8000-000000000001"
        admitted = command(ident)
        self.worker.retry_ambiguous("synthetic-op", binding, admitted)
        before = self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        with self.assertRaises(echo.EchoError):
            self.worker.retry_ambiguous("synthetic-op", binding, command(ident))
        self.assertEqual(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0],
            before,
        )
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(
            self.worker.inspect("synthetic-op", binding)["state"], "ambiguous"
        )
        self.worker._clock = lambda: 3000
        self.assertEqual(
            self.worker.retry_ambiguous("synthetic-op", binding, admitted)["state"],
            "ambiguous",
        )
        self.worker._clock = lambda: 1500
        self.transport.send = original
        self.assertEqual(
            self.worker.retry_ambiguous(
                "synthetic-op", binding, command("00000000-0000-4000-8000-000000000002")
            )["state"],
            "confirmed",
        )
        self.assertEqual(len(self.transport.calls), 3)

    def test_candidate_transcript_validated_before_storage(self):
        binding = self.admit()
        before = self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        record = json.loads(before)
        record["revision"] += 1
        with (
            self.assertRaisesRegex(echo.EchoError, "echo_proof_invalid"),
            self.journal._transaction(),
        ):
            self.journal._write(record)
        self.assertEqual(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0],
            before,
        )
        self.assertEqual(
            self.worker.advance("synthetic-op", binding)["state"], "confirmed"
        )

    def test_retry_freshness_after_verification_and_guard_wait(self):
        import threading
        from contextlib import contextmanager

        binding = self.admit()
        now = [1000]
        self.worker._clock = lambda: now[0]
        original = self.transport.send
        self.transport.send = lambda _: (_ for _ in ()).throw(TimeoutError())
        self.worker.advance("synthetic-op", binding)
        before = self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        prior = json.loads(before)["parts"][0]["attempts"][0]["attempt_id"]
        self.transport.send = original
        lock = threading.Lock()
        waiting = threading.Event()

        @contextmanager
        def guard():
            waiting.set()
            with lock:
                yield

        def verify(*args):
            now[0] = verify.observed
            return echo.RetryDecision(
                "00000000-0000-4000-8000-000000000001",
                "synthetic-owner",
                "synthetic-op",
                binding,
                prior,
                1000,
                2000,
                "duplicate-platform-post-accepted",
            )

        self.worker._verify_retry = verify
        self.worker._execution_guard = guard
        for observed in (2000, 3000, 999):
            verify.observed = observed
            now[0] = 1000
            with self.subTest(observed=observed):
                with self.assertRaisesRegex(echo.EchoError, "echo_retry_unauthorized"):
                    self.worker.retry_ambiguous("synthetic-op", binding, b"synthetic")
                self.assertEqual(
                    self.db.execute(
                        "SELECT record FROM echo_v2_obligations"
                    ).fetchone()[0],
                    before,
                )
                self.assertEqual(self.transport.calls, [])

        # Real contention: the command expires while waiting for the shared guard.
        now[0] = 1000
        verify.observed = 2000
        waiting.clear()
        lock.acquire()

        def release():
            waiting.wait(3)
            now[0] = 2000
            lock.release()

        thread = threading.Thread(target=release)
        thread.start()
        try:
            with self.assertRaisesRegex(echo.EchoError, "echo_retry_unauthorized"):
                self.worker.retry_ambiguous("synthetic-op", binding, b"synthetic")
        finally:
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.transport.calls, [])
        verify.observed = 1999
        now[0] = 1999
        self.assertEqual(
            self.worker.retry_ambiguous("synthetic-op", binding, b"synthetic")["state"],
            "confirmed",
        )
        self.assertEqual(
            self.worker.require_confirmed("synthetic-op", binding)["parts"][0][
                "attempts"
            ][-1]["at_ms"],
            1999,
        )

    def test_owner_verified_ambiguous_retry_retains_decision_and_is_idempotent(self):
        import hashlib
        import hmac
        from contextlib import contextmanager

        binding = self.admit()
        original = self.transport.send
        self.transport.send = lambda _: (_ for _ in ()).throw(TimeoutError("lost"))
        self.assertEqual(
            self.worker.advance("synthetic-op", binding)["state"], "ambiguous"
        )
        pending = json.loads(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        )
        prior = pending["parts"][0]["attempts"][0]["attempt_id"]
        now = [pending["parts"][0]["attempts"][0]["at_ms"] + 1]
        decision = {
            "authorization_id": "00000000-0000-4000-8000-000000000001",
            "actor": "synthetic-owner",
            "operation_id": "synthetic-op",
            "binding_digest": binding,
            "attempt_id": prior,
            "approved_at_ms": now[0],
            "expires_at_ms": now[0] + 1000,
            "risk": "duplicate-platform-post-accepted",
        }

        def envelope(value):
            body = echo._json(value).encode()
            return echo._json(
                {
                    "decision": value,
                    "signature": hmac.new(
                        b"o" * 32, b"owner-retry\0" + body, hashlib.sha256
                    ).hexdigest(),
                }
            ).encode()

        entered = []

        @contextmanager
        def guard():
            entered.append(True)
            try:
                yield
            finally:
                entered.pop()

        def verify(raw, exact_binding, attempt_id):
            self.assertTrue(entered)
            value = json.loads(raw)
            wanted = hmac.new(
                b"o" * 32,
                b"owner-retry\0" + echo._json(value["decision"]).encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(value["signature"], wanted):
                return None
            return echo.RetryDecision(**value["decision"])

        worker = echo.MandatoryEcho(
            self.journal,
            transport=self.transport,
            resolve=lambda _: self.source,
            authorize=lambda _: self.allowed,
            clock=lambda: now[0],
            verify_retry=verify,
            execution_guard=guard,
        )
        with self.assertRaisesRegex(echo.EchoError, "echo_retry_unauthorized"):
            worker.retry_ambiguous("synthetic-op", binding, b"unverified-command")
        with self.assertRaisesRegex(echo.EchoError, "echo_retry_unauthorized"):
            worker.retry_ambiguous(
                "synthetic-op",
                binding,
                envelope(
                    {**decision, "attempt_id": "00000000-0000-4000-8000-000000000002"}
                ),
            )
        self.transport.send = original
        authorization = envelope(decision)

        class Crash(BaseException):
            pass

        def lost_return(point):
            if point == "response_committed":
                raise Crash()

        worker._checkpoint = lost_return
        with self.assertRaises(Crash):
            worker.retry_ambiguous("synthetic-op", binding, authorization)
        self.assertEqual(
            worker.retry_ambiguous("synthetic-op", binding, authorization)["state"],
            "confirmed",
        )
        proof = worker.require_confirmed("synthetic-op", binding)
        attempts = proof["parts"][0]["attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertIsNone(attempts[0]["response"])
        self.assertEqual(attempts[1]["retry_authorization"]["decision"], decision)
        now[0] += 2000  # Historical decision stays valid; no new authorization.
        self.assertEqual(
            worker.retry_ambiguous("synthetic-op", binding, authorization)["state"],
            "confirmed",
        )
        self.assertEqual(len(self.transport.calls), 1)
        self.assertEqual(entered, [])

    def test_ambiguous_retry_crash_preserves_prefix_and_needs_new_decision(self):
        import threading
        from contextlib import contextmanager

        self.source = projection("x" * 7000)
        binding = self.admit()
        self.worker.advance("synthetic-op", binding)
        original = self.transport.send

        def lost(request):
            raise TimeoutError("synthetic lost result")

        self.transport.send = lost
        self.worker.advance("synthetic-op", binding)
        record = json.loads(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        )
        prefix = record["parts"][0]
        prior = record["parts"][1]["attempts"][-1]
        now = [prior["at_ms"] + 1]
        command_id = ["00000000-0000-4000-8000-000000000001"]

        def owner(raw, exact, attempt_id):
            return echo.RetryDecision(
                command_id[0],
                "synthetic-owner",
                "synthetic-op",
                binding,
                attempt_id,
                now[0],
                now[0] + 1000,
                "duplicate-platform-post-accepted",
            )

        lock = threading.Lock()

        @contextmanager
        def guard():
            with lock:
                yield

        worker = echo.MandatoryEcho(
            self.journal,
            transport=self.transport,
            resolve=lambda _: self.source,
            authorize=lambda _: self.allowed,
            clock=lambda: now[0],
            verify_retry=owner,
            execution_guard=guard,
        )

        class Crash(BaseException):
            pass

        def crash(point):
            if point == "response_verified":
                raise Crash()

        worker._checkpoint = crash
        self.transport.send = original
        with self.assertRaises(Crash):
            worker.retry_ambiguous(
                "synthetic-op", binding, b"synthetic-owner-command-1"
            )
        record = json.loads(
            self.db.execute("SELECT record FROM echo_v2_obligations").fetchone()[0]
        )
        self.assertEqual(record["parts"][0], prefix)
        self.assertEqual(len(record["parts"][1]["attempts"]), 2)
        self.assertIsNone(record["parts"][1]["attempts"][-1]["response"])
        self.assertEqual(
            worker.retry_ambiguous(
                "synthetic-op", binding, b"synthetic-owner-command-1"
            )["state"],
            "ambiguous",
        )
        self.assertEqual(len(self.transport.calls), 2)
        self.allowed = False
        with self.assertRaisesRegex(echo.EchoError, "echo_authorization_blocked"):
            worker.retry_ambiguous(
                "synthetic-op", binding, b"synthetic-owner-command-2"
            )
        self.allowed = True
        command_id[0] = "00000000-0000-4000-8000-000000000002"
        now[0] += 1
        worker._checkpoint = lambda point: None
        self.assertEqual(
            worker.retry_ambiguous(
                "synthetic-op", binding, b"synthetic-owner-command-2"
            )["state"],
            "queued",
        )
        self.assertEqual(worker.advance("synthetic-op", binding)["state"], "confirmed")
        self.assertEqual(
            worker.require_confirmed("synthetic-op", binding)["parts"][0], prefix
        )
        self.assertEqual(len(self.transport.calls), 4)

    def test_shared_execution_guard_fences_live_send_from_owner_recovery(self):
        import threading
        from contextlib import contextmanager

        binding = self.admit()
        lock = threading.Lock()
        entered, finish, retry_started, retry_done = (
            threading.Event() for _ in range(4)
        )
        results, errors = [], []
        original = self.transport.send

        def blocked(request):
            entered.set()
            if not finish.wait(5):
                raise RuntimeError("test timeout")
            return original(request)

        self.transport.send = blocked

        @contextmanager
        def guard():
            with lock:
                yield

        def run(recovery):
            db = self.connect()
            try:
                worker = echo.MandatoryEcho(
                    self.reopen(db),
                    transport=self.transport,
                    resolve=lambda _: self.source,
                    authorize=lambda _: True,
                    verify_retry=lambda *args: None,
                    execution_guard=guard,
                )
                if recovery:
                    retry_started.set()
                    results.append(
                        worker.retry_ambiguous(
                            "synthetic-op", binding, b"unused-owner-command"
                        )
                    )
                    retry_done.set()
                else:
                    results.append(worker.advance("synthetic-op", binding))
            except BaseException as exc:
                errors.append(exc)
            finally:
                db.close()

        first = threading.Thread(target=run, args=(False,))
        second = threading.Thread(target=run, args=(True,))
        first.start()
        try:
            self.assertTrue(entered.wait(3))
            second.start()
            self.assertTrue(retry_started.wait(3))
            self.assertFalse(retry_done.wait(0.05))
        finally:
            finish.set()
            first.join(5)
            if second.ident is not None:
                second.join(5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([r["state"] for r in results], ["confirmed", "confirmed"])
        self.assertEqual(len(self.transport.calls), 1)

    def test_atomic_admission_complete_echo_and_restart_gate(self):
        binding = self.admit()
        self.assertEqual(
            self.worker.inspect("synthetic-op", binding)["state"], "queued"
        )
        with self.assertRaisesRegex(echo.EchoError, "echo_not_confirmed"):
            self.worker.require_confirmed("synthetic-op", binding)
        self.assertEqual(
            self.worker.advance("synthetic-op", binding)["state"], "confirmed"
        )
        proof = self.worker.require_confirmed("synthetic-op", binding)
        self.assertEqual(proof["binding"]["projection"], self.source)
        self.assertEqual(len(self.transport.calls), 1)
        other = self.connect()
        try:
            reopened = self.worker_for(self.reopen(other))
            self.assertEqual(
                reopened.advance("synthetic-op", binding)["state"], "confirmed"
            )
            self.assertEqual(reopened.require_confirmed("synthetic-op", binding), proof)
            self.assertEqual(len(self.transport.calls), 1)
        finally:
            other.close()
        self.allowed = False
        with self.assertRaisesRegex(echo.EchoError, "echo_authorization_blocked"):
            self.worker.require_confirmed("synthetic-op", binding)


if __name__ == "__main__":
    unittest.main()
