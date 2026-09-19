"""Offline registration and real pinned Hermes tests; never real credentials."""

import hashlib
import http.server
import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing, suppress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix.execution_instruction import ExecutionDenied, Instruction
from daimon_matrix.execution_store import ExecutionStore
from daimon_matrix.review_runner import ReviewController
from tests.test_execution_instruction import proof, request, verifier
from tests.test_passive_messaging_execution import Broker


def registration(**changes):
    value = dict(
        schema="execution/v1/hermes-registration",
        principal="human:test",
        store_id="store:test",
        being="being:test",
        embodiment="body:test",
        runner="runner:test",
        session="session:test",
        provider="custom",
        model="synthetic-review",
        api_mode="chat_completions",
        endpoint="http://127.0.0.1:12345/v1/chat/completions",
        source_commit="5c8870c1625761956a56fd2b225720dbe9083e45",
        source_archive_sha256=(
            "09789981423142fec1a26239d5209f96c41453078ff73e2fc4a11e1d45728660"
        ),
        python_sha256="a" * 64,
        environment_sha256="b" * 64,
        profile="/tmp/owned-review",
        expires=200,
        mode="ephemeral-review",
        max_response_bytes=65536,
        token_accounting="utf8-bytes-upper-bound-v1",
    )
    return value | changes


class RegistrationTests(unittest.TestCase):
    def test_separate_registration_schema_matches_closed_runtime_shape(self):
        import jsonschema

        from daimon_matrix.hermes_review import Registration

        path = (
            Path(__file__).resolve().parents[1]
            / "schemas/execution/v1/hermes-registration.schema.json"
        )
        self.assertTrue(
            path.is_file(), "separately versioned registration schema missing"
        )
        schema = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        payload = registration()
        self.assertEqual(list(validator.iter_errors(payload)), [])
        key = Ed25519PrivateKey.generate()
        for changes in (
            {"extra": True},
            {"model": "*"},
            {"api_mode": "responses"},
            {"max_response_bytes": True},
            {"expires": 0},
            {"profile": "relative"},
            {"source_commit": "0" * 40},
            {"python_sha256": "X" * 64},
        ):
            bad = payload | changes
            with self.subTest(changes=changes):
                self.assertTrue(list(validator.iter_errors(bad)))
                with self.assertRaises(ExecutionDenied):
                    Registration.verify(
                        bad, proof(key, "approve", bad), verifier(key), lambda _: True
                    )
        for key_name in payload:
            self.assertTrue(
                list(
                    validator.iter_errors(
                        {k: v for k, v in payload.items() if k != key_name}
                    )
                )
            )

    def test_signed_closed_registration_preserves_selection(self):
        self.assertIsNotNone(importlib.util.find_spec("daimon_matrix.hermes_review"))
        from daimon_matrix.hermes_review import Registration

        key = Ed25519PrivateKey.generate()
        payload = registration()
        result = Registration.verify(
            payload, proof(key, "approve", payload), verifier(key), lambda _: True
        )
        self.assertEqual(
            result.binding, ("being:test", "body:test", "runner:test", "session:test")
        )
        self.assertEqual(
            (result.provider, result.model, result.api_mode),
            ("custom", "synthetic-review", "chat_completions"),
        )
        for changes in (
            {"human": True},
            {"mode": "memory"},
            {"source_commit": "0" * 40},
            {"max_response_bytes": True},
            {"token_accounting": "unqualified"},
            {"endpoint": "http://example.org/v1/chat/completions"},
        ):
            bad = payload | changes
            with self.subTest(changes=changes), self.assertRaises(ExecutionDenied):
                Registration.verify(
                    bad, proof(key, "approve", bad), verifier(key), lambda _: True
                )
        with self.assertRaises(ExecutionDenied):
            Registration.verify(
                payload | {"model": "substituted"},
                proof(key, "approve", payload),
                verifier(key),
                lambda _: True,
            )
        with self.assertRaises(ExecutionDenied):
            Registration.verify(
                payload, proof(key, "approve", payload), verifier(key), lambda _: False
            )


class StrictJSONTests(unittest.TestCase):
    def test_bounded_strict_json(self):
        from daimon_matrix.hermes_review import strict_json

        self.assertEqual(
            strict_json(b'{"ok":[1,0.5,true,null]}'), {"ok": [1, 0.5, True, None]}
        )
        for raw in (
            b'{"x":1,"x":2}',
            b"{",
            b"NaN",
            b"Infinity",
            b"1e999",
            b'"\\ud800"',
            b"9007199254740992",
            b"\xff",
            b"[" * 65 + b"0" + b"]" * 65,
            b'"' + b"a" * 1048576 + b'"',
        ):
            with self.subTest(prefix=raw[:30]), self.assertRaises(ExecutionDenied):
                strict_json(raw)


class GateTests(unittest.IsolatedAsyncioTestCase):
    """Real host HTTP gate; isolated context stand-in, not actual Hermes."""

    async def test_startup_metadata_is_local_non_authorizing(self):
        import asyncio

        from daimon_matrix.hermes_review import ChatGate, Registration

        gate = ChatGate(
            Registration(**registration()),
            None,
            lambda: self.fail("metadata checked execution authority"),
            lambda _: self.fail("metadata consulted provider auth"),
            "dummy",
        )
        server = await asyncio.start_server(gate.handle, "127.0.0.1", 0)
        try:
            for method, path, body in (
                ("GET", "/v1/models", b""),
                ("POST", "/api/show", b'{"name":"synthetic-review"}'),
            ):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", server.sockets[0].getsockname()[1]
                )
                writer.write(
                    (
                        f"{method} {path} HTTP/1.1\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n"
                    ).encode()
                    + body
                )
                await writer.drain()
                response = await reader.read()
                writer.close()
                await writer.wait_closed()
                self.assertTrue(response.startswith(b"HTTP/1.1 404"), response)
                self.assertIsNone(gate.error)
                self.assertFalse(gate.claimed or gate.sent or gate.confirmed)
        finally:
            server.close()
            await server.wait_closed()
            await gate.close()


class GateBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """Real TCP gate + upstream and real SQLite/CycleContext, without a worker."""

    async def asyncSetUp(self):
        import asyncio

        from daimon_matrix.hermes_review import ChatGate, Registration, read_http
        from daimon_matrix.review_runner import CycleContext

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Ed25519PrivateKey.generate()
        self.store = ExecutionStore.create(
            Path(self.tmp.name) / "execution.sqlite", verifier(self.key)
        )
        now = int(time.time())
        self.instruction = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                start=now,
                end=now + 60,
                max_cycle_seconds=60,
                provider="custom",
                model="synthetic-review",
                max_input_tokens=10000,
                max_output_tokens=1000,
            )
        )
        self.store.approve(
            self.instruction, proof(self.key, "approve", self.instruction.to_dict())
        )
        self.cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        self.context = CycleContext(
            self.store,
            self.cycle,
            self.instruction,
            Broker(),
            time.monotonic,
            time.monotonic() + 60,
        )
        self.calls = []
        self.response = {
            "id": "synthetic",
            "object": "chat.completion",
            "created": 1,
            "model": "synthetic-review",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": '{"action":"none"}'},
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }
        self.raw_response = None
        self.status_code = 200
        self.release = asyncio.Event()
        self.release.set()
        self.received = asyncio.Event()
        self.upstream_tasks = set()

        async def upstream(reader, writer):
            task = asyncio.current_task()
            self.upstream_tasks.add(task)
            try:
                value = await read_http(reader, 1048576, request=True)
                self.calls.append(value)
                self.received.set()
                await self.release.wait()
                raw = (
                    self.raw_response
                    if self.raw_response is not None
                    else json.dumps(self.response).encode()
                )
                writer.write(
                    (
                        f"HTTP/1.1 {self.status_code} Response\r\n"
                        f"Content-Length: {len(raw)}\r\n\r\n"
                    ).encode()
                    + raw
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                self.upstream_tasks.discard(task)

        self.upstream = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = self.upstream.sockets[0].getsockname()[1]
        self.gate = ChatGate(
            Registration(
                **registration(endpoint=f"http://127.0.0.1:{port}/v1/chat/completions")
            ),
            self.context,
            self.context.check,
            lambda _: {"Authorization": "Bearer host-only"},
            "dummy",
        )
        self.server = await asyncio.start_server(
            self.gate.handle, "127.0.0.1", 0, limit=16385
        )
        self.body = {
            "model": "synthetic-review",
            "messages": [{"role": "user", "content": "review"}],
            "max_tokens": 1000,
        }

    async def asyncTearDown(self):
        import asyncio

        self.release.set()
        await self.gate.close()
        for task in tuple(self.upstream_tasks):
            task.cancel()
        await asyncio.gather(*self.upstream_tasks, return_exceptions=True)
        for server in (self.server, self.upstream):
            server.close()
            await server.wait_closed()

    async def send(
        self, body=None, route="/v1/chat/completions", token="dummy", extra=b""
    ):
        import asyncio

        raw = (
            json.dumps(self.body if body is None else body).encode()
            if not isinstance(body, bytes)
            else body
        )
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.server.sockets[0].getsockname()[1]
        )
        writer.write(
            (
                f"POST {route} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n"
                f"Content-Length: {len(raw)}\r\n"
            ).encode()
            + extra
            + b"\r\n"
            + raw
        )
        await writer.drain()
        try:
            result = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        finally:
            writer.close()
            with suppress(ConnectionResetError):
                await writer.wait_closed()
        return result

    def cancel(self):
        payload = self.store.cancellation_payload("review-1", 1)
        self.store.cancel("review-1", 1, proof(self.key, "cancel", payload, "cancel"))

    async def test_second_summary_fallback_and_concurrent_requests_submit_once(
        self,
    ):
        import asyncio

        outputs = await asyncio.gather(
            self.send(), self.send(), self.send(self.body | {"model": "fallback"})
        )
        self.assertEqual(sum(o.startswith(b"HTTP/1.1 200") for o in outputs), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(
            (
                await self.send(
                    self.body | {"messages": [{"role": "user", "content": "summarize"}]}
                )
            ).startswith(b"HTTP/1.1 400")
        )
        self.assertEqual(len(self.calls), 1)
        operations = self.store.cycle_status(self.cycle.cycle_id)["operations"]
        self.assertEqual([o["kind"] for o in operations], ["provider"])
        self.assertEqual(self.calls[0][1]["authorization"], "Bearer host-only")

    async def test_sdk_retry_after_upstream_error_never_resubmits(self):
        self.status_code = 503
        for _ in range(3):
            self.assertTrue((await self.send()).startswith(b"HTTP/1.1 400"))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.gate.sent)
        self.assertFalse(self.gate.confirmed)

    async def test_cancellation_before_enqueue_has_zero_submissions(self):
        self.cancel()
        self.assertTrue((await self.send()).startswith(b"HTTP/1.1 400"))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.store.cycle_status(self.cycle.cycle_id)["operations"], [])

    async def test_cancellation_after_enqueue_late_response_is_evidence_only(self):
        import asyncio

        self.release.clear()
        sending = asyncio.create_task(self.send())
        await asyncio.wait_for(self.received.wait(), 2)
        self.cancel()
        self.release.set()
        self.assertTrue((await sending).startswith(b"HTTP/1.1 400"))
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.gate.confirmed)

    async def test_strict_request_controls_fail_before_upstream(self):
        # Reset only the local gate's one-shot reservation between independent bad
        # inputs; the real provider admission journal must remain empty.
        bad = [
            self.body | update
            for update in (
                {"model": "other"},
                {"tools": [{"type": "function"}]},
                {"functions": []},
                {"stream": "false"},
                {"stream_options": {"include_usage": False}},
                {"messages": [{"role": "tool", "content": "x"}]},
                {"temperature": "hot"},
                {"top_p": True},
                {"max_tokens": True},
                {"tool_choice": {"type": "function"}},
                {"messages": [{"role": "user", "content": "x" * 10001}]},
            )
        ]
        bad += [
            b'{"model":"synthetic-review","model":"synthetic-review"}',
            b"{",
            b"1e999",
        ]
        for value in bad:
            with self.subTest(value=str(value)[:80]):
                self.gate.claimed = False
                self.assertTrue((await self.send(value)).startswith(b"HTTP/1.1 400"))
                self.assertEqual(self.calls, [])
        self.assertEqual(self.store.cycle_status(self.cycle.cycle_id)["operations"], [])

    async def test_wrong_routes_credentials_framing_and_oversize(self):
        for kwargs in (
            {"route": "/v1/responses"},
            {"token": "wrong"},
            {"extra": b"Content-Length: 2\r\n"},
            {"extra": b"Transfer-Encoding: chunked\r\n"},
            {"body": b"x" * 1048577},
            {"route": "/api/show", "body": {"name": "wrong"}},
        ):
            with self.subTest(kwargs=str(kwargs)[:60]):
                self.assertTrue((await self.send(**kwargs)).startswith(b"HTTP/1.1 400"))
        self.assertEqual(self.calls, [])


def _gate_bad_response_case(kind):
    async def test(self):
        if kind == "object":
            self.response["object"] = {"hidden": "metadata"}
        elif kind == "created":
            self.response["created"] = True
        elif kind == "fingerprint":
            self.response["system_fingerprint"] = ["hidden"]
        elif kind == "missing_metadata":
            del self.response["object"]
        elif kind == "usage_bool":
            self.response["usage"]["prompt_tokens"] = True
        elif kind == "usage_total":
            self.response["usage"]["total_tokens"] = 1
        elif kind == "text_budget":
            self.response["choices"][0]["message"]["content"] = "x" * 1001
        elif kind == "hidden_reasoning":
            self.response["choices"][0]["message"]["reasoning_content"] = "hidden"
        elif kind == "truncated":
            self.response["choices"][0]["finish_reason"] = "length"
        self.assertTrue((await self.send()).startswith(b"HTTP/1.1 400"))
        self.assertTrue(self.gate.sent)
        self.assertFalse(self.gate.confirmed)
        self.assertEqual(len(self.calls), 1)

    return test


for _case in (
    "object",
    "created",
    "fingerprint",
    "missing_metadata",
    "usage_bool",
    "usage_total",
    "text_budget",
    "hidden_reasoning",
    "truncated",
):
    setattr(
        GateBoundaryTests,
        "test_response_rejects_" + _case,
        _gate_bad_response_case(_case),
    )


ARCHIVE = os.environ.get("HERMES_REVIEW_ARCHIVE")
PYTHON = os.environ.get("HERMES_REVIEW_PYTHON")


@unittest.skipUnless(
    ARCHIVE and PYTHON, "set exact archive and isolated pinned dependency venv"
)
class ActualHermesTests(unittest.TestCase):
    def setUp(self):
        import gc
        import sys
        import warnings

        from daimon_matrix import hermes_review as h

        unraisables = []
        original_hook = sys.unraisablehook
        warning_context = warnings.catch_warnings()
        warning_context.__enter__()
        warnings.simplefilter("error", ResourceWarning)
        sys.unraisablehook = lambda event: unraisables.append(str(event.exc_value))

        def verify_cleanup():
            try:
                gc.collect()
            finally:
                sys.unraisablehook = original_hook
                warning_context.__exit__(None, None, None)
            self.assertEqual(unraisables, [], "cleanup must not leak resources")

        # Registered first, so collection follows runner/server/directory cleanup.
        self.addCleanup(verify_cleanup)
        self.assertTrue(hasattr(h, "HermesReviewRunner"), "bounded runner missing")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / "runtime"
        self.profile.mkdir(mode=0o700)
        self.key = Ed25519PrivateKey.generate()
        self.verifier = verifier(self.key)
        self.store = ExecutionStore.create(
            self.root / "execution.sqlite", self.verifier
        )
        self.calls = []
        self.received = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.addCleanup(self.release.set)
        self.response_text = '{"scope":1,"text":"Synthetic reply"}'
        self.response_override = None
        self.http_status = 200
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.calls.append((self.path, dict(self.headers), json.loads(body)))
                owner.received.set()
                owner.release.wait(90)
                raw = (
                    owner.response_override
                    or json.dumps(
                        {
                            "id": "synthetic-completion",
                            "object": "chat.completion",
                            "created": 1,
                            "model": "synthetic-review",
                            "choices": [
                                {
                                    "index": 0,
                                    "finish_reason": "stop",
                                    "message": {
                                        "role": "assistant",
                                        "content": owner.response_text,
                                    },
                                }
                            ],
                            "usage": {
                                "prompt_tokens": 10,
                                "completion_tokens": 10,
                                "total_tokens": 20,
                            },
                        }
                    ).encode()
                )
                self.send_response(owner.http_status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                with suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(raw)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.payload = registration(
            profile=str(self.profile),
            store_id=self.store.store_id,
            endpoint=f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions",
            expires=int(time.time()) + 120,
            python_sha256=hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest(),
            environment_sha256=h.environment_digest(Path(PYTHON).parent.parent),
        )
        self.task = "Review this synthetic scoped inbox only."
        now = int(time.time())
        self.instruction = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                start=now,
                end=now + 90,
                mode="manual",
                interval=None,
                max_cycles=1,
                max_cycle_seconds=30,
                max_input_tokens=60000,
                max_output_tokens=2000,
                provider=self.payload["provider"],
                model=self.payload["model"],
                task_sha256=hashlib.sha256(self.task.encode()).hexdigest(),
                scope=[
                    dict(
                        channel="channel:test",
                        thread="thread:test",
                        tool="messaging_inbox",
                        action="review",
                    ),
                    dict(
                        channel="channel:test",
                        thread="thread:test",
                        tool="messaging_reply",
                        action="reply",
                    ),
                ],
            )
        )
        self.runner = h.HermesReviewRunner(
            self.payload,
            proof(self.key, "approve", self.payload),
            self.verifier,
            existing_body=lambda _: True,
            source_archive=Path(ARCHIVE),
            python=Path(PYTHON),
            provider_headers=lambda _: {
                "Authorization": "Bearer synthetic-host-only",
                "X-Synthetic": "preserved",
            },
        )
        self.addCleanup(self.runner.close)
        self.broker = Broker()
        self.controller = ReviewController(self.store, self.runner, self.broker)

    def stop_server(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)

    def approve(self):
        self.store.approve(
            self.instruction,
            proof(self.key, "approve", self.instruction.to_dict(), "instruction"),
        )

    def run_cycle(self):
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertIsNotNone(context)
        self.assertTrue(self.runner.wait(context.cycle.cycle_id, 42))
        return context, self.runner.status(context.cycle.cycle_id)

    def test_cross_principal_instruction_is_denied_before_any_durable_intent(self):
        from daimon_matrix.execution_instruction import (
            ApprovalVerifier,
            canonical,
            digest,
        )

        other_key = Ed25519PrivateKey.generate()
        trusted = ApprovalVerifier(
            {
                "human:test": self.key.public_key(),
                "human:other": other_key.public_key(),
            }
        )
        self.store.verifier = trusted
        self.instruction = replace(self.instruction, principal="human:other")
        approval_body = {
            "purpose": "execution/v1/approve",
            "event_id": "other-human-approval",
            "principal": "human:other",
            "payload_sha256": digest(self.instruction.to_dict()),
        }
        approval = approval_body | {
            "signature": other_key.sign(canonical(approval_body)).hex()
        }
        self.store.approve(self.instruction, approval)

        with self.assertRaisesRegex(ExecutionDenied, "registered"):
            self.controller.run_due_once("review-1", 1, self.task)

        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM cycles").fetchone()[0], 0)
            self.assertEqual(
                db.execute("SELECT count(*) FROM operations").fetchone()[0], 0
            )
        with closing(sqlite3.connect(self.runner._path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM runtime").fetchone()[0], 0
            )
        self.assertIsNone(self.runner._thread)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])

    def test_same_principal_instruction_enters_real_runner_control(self):
        reached, release = threading.Event(), threading.Event()
        original = self.runner._validate_environment

        def hold():
            reached.set()
            if not release.wait(5):
                raise ExecutionDenied("test barrier timeout")
            original()

        self.runner._validate_environment = hold
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(reached.wait(2))
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM cycles").fetchone()[0], 1)
            self.assertEqual(
                db.execute("SELECT count(*) FROM operations").fetchone()[0], 1
            )
        with closing(sqlite3.connect(self.runner._path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM runtime").fetchone()[0], 1
            )
        release.set()
        self.assertTrue(self.runner.wait(context.cycle.cycle_id, 42))
        self.assertEqual(
            self.controller.cancel_active("review-1", 1, 1), ("stopped", ())
        )

    def test_actual_hermes_boundary_does_not_observe_native_arrival(self):
        from tests.test_passive_messaging_execution import (
            deliver_store_mirror_without_execution,
        )

        counts = deliver_store_mirror_without_execution(self.root / "passive")
        self.assertIsNone(self.controller.run_due_once("absent", 1, self.task))
        self.assertEqual(counts, {"stored": 1, "mirrored": 1, "automatic_reply": 0})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])

    def test_real_AIAgent_one_request_scoped_reply_and_no_ambient_state(self):
        self.assertIsNone(self.controller.run_due_once("absent", 1, self.task))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "completed", status)
        self.assertEqual(len(self.calls), 1)
        path, headers, body = self.calls[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer synthetic-host-only")
        self.assertEqual(headers["X-Synthetic"], "preserved")
        self.assertEqual(body["tools"], [])
        self.assertEqual(body["tool_choice"], "none")
        self.assertFalse(body["stream"])
        self.assertEqual(body["model"], "synthetic-review")
        self.assertEqual(len(self.broker.calls), 2)
        self.assertEqual(self.broker.calls[1][0], self.instruction.scope[1])
        self.assertEqual(self.broker.calls[1][1], {"text": "Synthetic reply"})
        evidence = json.loads(status["result"])
        self.assertEqual(evidence["tools"], [])
        self.assertEqual(
            (evidence["provider"], evidence["model"], evidence["api_mode"]),
            (self.payload["provider"], self.payload["model"], self.payload["api_mode"]),
        )
        self.assertEqual(evidence["session_id"], status["session_id"])
        self.assertEqual(evidence["task_id"], context.cycle.cycle_id)
        self.assertTrue(evidence["isolated_network"])
        self.assertNotIn("OPENAI_API_KEY", evidence["environment_keys"])
        self.assertNotIn("HERMES_KANBAN_TASK", evidence["environment_keys"])
        self.assertTrue(status["reaped"])
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "completed"
        )
        operations = self.store.cycle_status(context.cycle.cycle_id)["operations"]
        self.assertEqual(
            [o["kind"] for o in operations],
            ["inference", "native", "provider", "native"],
        )
        self.assertFalse(
            any(
                name.endswith(("MEMORY.md", "USER.md", "auth.json"))
                for name in evidence["home_files"]
            )
        )
        self.assertIn("SOUL.md", evidence["home_files"])
        self.assertEqual(
            evidence["seeded_soul_sha256"],
            "2765a846e1bb371d78d3b93b403dfb0f8d1ba1a9895edb5f608367abfe81194d",
        )

    def cancel(self):
        payload = self.store.cancellation_payload("review-1", 1)
        self.store.cancel("review-1", 1, proof(self.key, "cancel", payload, "cancel"))

    def test_cancelled_approval_launches_nothing(self):
        self.approve()
        self.cancel()
        self.assertIsNone(self.controller.run_due_once("review-1", 1, self.task))
        self.assertIsNone(self.runner._thread)
        self.assertEqual((self.calls, self.broker.calls), ([], []))

    def test_expired_approval_launches_nothing(self):
        self.approve()
        self.store.clock = lambda: self.instruction.end
        self.assertIsNone(self.controller.run_due_once("review-1", 1, self.task))
        self.assertIsNone(self.runner._thread)
        self.assertEqual((self.calls, self.broker.calls), ([], []))

    def test_concurrent_controller_admission_has_one_worker(self):
        from concurrent.futures import ThreadPoolExecutor

        self.approve()
        with ThreadPoolExecutor(2) as pool:
            results = list(
                pool.map(
                    lambda _: self.controller.run_due_once("review-1", 1, self.task),
                    range(2),
                )
            )
        contexts = [r for r in results if r is not None]
        self.assertEqual(len(contexts), 1)
        self.assertTrue(self.runner.wait(contexts[0].cycle.cycle_id, 22))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(
            self.runner.status(contexts[0].cycle.cycle_id)["state"], "completed"
        )

    def test_real_retry_error_reaped_and_restart_never_resubmits(self):
        from daimon_matrix.hermes_review import HermesReviewRunner

        self.http_status = 503
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.broker.calls), 1)
        self.assertEqual(self.runner.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.runner.close()
        reopened = HermesReviewRunner(
            self.payload,
            proof(self.key, "approve", self.payload),
            self.verifier,
            existing_body=lambda _: True,
            source_archive=Path(ARCHIVE),
            python=Path(PYTHON),
            provider_headers=lambda _: {},
        )
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.status(context.cycle.cycle_id)["state"], "ambiguous")
        controller = ReviewController(
            ExecutionStore(self.store.path, self.verifier), reopened, self.broker
        )
        self.assertIsNone(controller.run_due_once("review-1", 1, self.task))
        self.assertEqual(reopened.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.assertEqual(len(self.calls), 1)
        reopened.close()
        journal = self.profile / "hermes.sqlite"
        journal.rename(self.root / "lost-runtime.sqlite")
        with self.assertRaises(ExecutionDenied):
            unexpected = HermesReviewRunner(
                self.payload,
                proof(self.key, "approve", self.payload),
                self.verifier,
                existing_body=lambda _: True,
                source_archive=Path(ARCHIVE),
                python=Path(PYTHON),
                provider_headers=lambda _: {},
            )
            self.addCleanup(unexpected.close)
        self.assertFalse(
            journal.exists(), "lost initialized state must not be recreated"
        )
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "ambiguous"
        )
        self.assertEqual(len(self.calls), 1)

    def test_cancel_inflight_unknown_reaps_exact_process(self):
        self.instruction = replace(self.instruction, max_cycle_seconds=15)
        self.release.clear()
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(self.received.wait(32))
        self.assertEqual(self.runner.interrupt("wrong-cycle", 0.1), "unknown")
        self.cancel()
        self.assertEqual(self.runner.interrupt(context.cycle.cycle_id, 3), "unknown")
        self.assertTrue(self.runner.wait(context.cycle.cycle_id, 5))
        status = self.runner.status(context.cycle.cycle_id)
        self.assertTrue(status["reaped"])
        self.assertEqual(status["state"], "ambiguous")
        self.assertEqual(len(self.broker.calls), 1)
        self.assertEqual(len(self.calls), 1)
        self.release.set()

    def test_expiry_stalled_response_retains_ambiguity(self):
        self.instruction = replace(self.instruction, max_cycle_seconds=15)
        self.release.clear()
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"])
        self.assertEqual(self.runner.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))
        self.release.set()

    def test_deadline_survives_blocked_execution_journal(self):
        self.instruction = replace(self.instruction, max_cycle_seconds=15)
        import sqlite3

        self.release.clear()
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(self.received.wait(32))
        pid = self.runner.status(context.cycle.cycle_id)["pid"]
        lock = sqlite3.connect(self.store.path)
        lock.execute("BEGIN IMMEDIATE")
        try:
            limit = time.monotonic() + 18
            while process_live(pid) and time.monotonic() < limit:
                time.sleep(0.05)
            self.assertFalse(
                process_live(pid),
                "independent OS timer must kill even when context.check is blocked",
            )
        finally:
            lock.rollback()
            lock.close()
        self.assertTrue(self.runner.wait(context.cycle.cycle_id, 42))
        status = self.runner.status(context.cycle.cycle_id)
        self.assertTrue(status["reaped"])
        self.assertEqual(status["state"], "ambiguous")
        self.assertEqual(self.runner.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.release.set()

    def test_oversized_worker_result_is_drained_and_reaped(self):
        import asyncio
        from unittest.mock import patch

        original = asyncio.create_subprocess_exec
        processes = []

        async def flood(*args, **kwargs):
            args = list(args)
            self.assertEqual(args[-1], "/worker.py")
            args[-1:] = [
                "-c",
                "import os,time; os.write(1,b'x'*(4*1048576)); time.sleep(60)",
            ]
            process = await original(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(asyncio, "create_subprocess_exec", flood):
            _context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"], status)
        self.assertEqual(self.calls, [])
        self.assertFalse(process_live(status["pid"]))
        self.assertTrue(
            processes[0].stdout.at_eof(), "reaped pipe must be bounded-drained"
        )

    def test_native_failure_retains_ambiguity_after_provider_settlement(self):
        original = self.broker.submit

        def lost_receipt(scope, payload, timeout):
            result = original(scope, payload, timeout)
            if scope.tool == "messaging_reply":
                raise ConnectionError("synthetic native settlement unknown")
            return result

        self.broker.submit = lost_receipt
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertEqual(status["response_id"], "synthetic-completion")
        self.assertTrue(status["reaped"])
        self.assertEqual(self.runner.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 2))

    def test_native_budget_counts_inbox_and_prevents_second_effect(self):
        self.instruction = replace(self.instruction, max_effects=1)
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"])
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))
        operations = self.store.cycle_status(context.cycle.cycle_id)["operations"]
        self.assertEqual(sum(o["kind"] == "native" for o in operations), 1)

    def test_close_timeout_keeps_lock_and_allows_later_reaping(self):
        import fcntl
        from types import SimpleNamespace

        alive = [True]
        self.runner._thread = SimpleNamespace(
            join=lambda _: None, is_alive=lambda: alive[0]
        )
        with self.assertRaises(ExecutionDenied):
            self.runner.close()
        self.assertFalse(self.runner._closed)
        self.assertTrue(self.runner.source.exists())
        fd = os.open(self.profile / "hermes.lock", os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            alive[0] = False
            self.runner.close()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            alive[0] = False
            os.close(fd)
        self.assertTrue(self.runner._closed)
        self.assertFalse(self.runner.source.exists())

    def test_close_serializes_with_start_and_retains_ownership(self):
        from types import SimpleNamespace

        from daimon_matrix.review_runner import CycleContext, ReviewRequest

        entered, release = threading.Event(), threading.Event()

        def join(_):
            entered.set()
            release.wait(3)

        self.runner._thread = SimpleNamespace(join=join, is_alive=lambda: False)
        launched = []
        self.runner._supervise = lambda *args: launched.append(True)
        self.approve()
        cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        context = CycleContext(
            self.store,
            cycle,
            self.instruction,
            self.broker,
            time.monotonic,
            time.monotonic() + 15,
        )
        review = ReviewRequest(
            self.instruction, self.task, cycle.cycle_id, cycle.deadline
        )
        closer = threading.Thread(target=self.runner.close)
        closer.start()
        try:
            self.assertTrue(entered.wait(1))
            with self.assertRaises(ExecutionDenied):
                self.runner.start(review, context, 0.1)
            self.assertEqual(launched, [])
        finally:
            release.set()
            closer.join(5)
        self.assertFalse(closer.is_alive())
        self.assertTrue(self.runner._closed)

    def test_interrupt_serializes_exact_cycle_against_new_start(self):
        from types import SimpleNamespace

        from daimon_matrix.review_runner import CycleContext, ReviewRequest

        entered, release = threading.Event(), threading.Event()

        def join(_):
            entered.set()
            release.wait(3)

        self.runner._thread = SimpleNamespace(join=join, is_alive=lambda: False)
        self.runner._cycle_id = "old-cycle"
        self.runner._supervise = lambda *args: None
        self.approve()
        cycle = self.store.reserve("review-1", 1, self.instruction.binding)
        context = CycleContext(
            self.store,
            cycle,
            self.instruction,
            self.broker,
            time.monotonic,
            time.monotonic() + 15,
        )
        review = ReviewRequest(
            self.instruction, self.task, cycle.cycle_id, cycle.deadline
        )
        stopping = threading.Thread(
            target=lambda: self.runner.interrupt("old-cycle", 3)
        )
        stopping.start()
        try:
            self.assertTrue(entered.wait(1))
            with self.assertRaises(ExecutionDenied):
                self.runner.start(review, context, 0.1)
            self.assertEqual(self.runner._cycle_id, "old-cycle")
        finally:
            release.set()
            stopping.join(5)
        self.assertFalse(stopping.is_alive())

    def test_constructor_failure_cleans_extracted_source_immediately(self):
        from unittest.mock import patch

        from daimon_matrix import hermes_review as h

        original = tempfile.TemporaryDirectory
        created = []

        def remember(*args, **kwargs):
            directory = original(*args, **kwargs)
            created.append(
                directory
            )  # Retain object: GC must not be the cleanup boundary.
            return directory

        payload = self.payload | {"profile": str(self.root / "nonexistent")}
        try:
            with (
                patch.object(h.tempfile, "TemporaryDirectory", remember),
                self.assertRaises(FileNotFoundError),
            ):
                h.HermesReviewRunner(
                    payload,
                    proof(self.key, "approve", payload),
                    self.verifier,
                    existing_body=lambda _: True,
                    source_archive=Path(ARCHIVE),
                    python=Path(PYTHON),
                    provider_headers=lambda _: {},
                )
            self.assertEqual(len(created), 1)
            self.assertFalse(Path(created[0].name).exists())
        finally:
            for directory in created:
                directory.cleanup()

    def test_worker_result_closed_before_native_proposal(self):
        from unittest.mock import patch

        from daimon_matrix import hermes_review as h

        original = h.strict_json

        def injected(raw):
            value = original(raw)
            if isinstance(value, dict) and value.get("isolated_network") is True:
                value["unapproved_metadata"] = "not in result grammar"
            return value

        with patch.object(h, "strict_json", injected):
            _context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"])
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))

    def test_actual_sandbox_denies_host_file_direct_network_and_ambient_secrets(self):
        import asyncio
        from unittest.mock import patch

        sentinel = self.root / "host-only-secret-sentinel"
        sentinel.write_text("synthetic-not-a-secret")
        wrapper = self.root / "probe.py"
        wrapper.write_text(
            """import os, socket, runpy, sys
from pathlib import Path
assert sys.dont_write_bytecode and sys.pycache_prefix == "/tmp/pycache"
assert not Path("/tmp/pycache").exists()
assert not Path(SENTINEL).exists()
assert "DM138_SYNTHETIC_SECRET" not in os.environ
s = socket.socket()
s.settimeout(.2)
assert s.connect_ex(("127.0.0.1", PORT)) != 0
s.close()
import builtins
original_import = builtins.__import__
# Instrument only the real prompt loader after the worker initializes its home.
def instrumented_import(name, *args, **kwargs):
    module = original_import(name, *args, **kwargs)
    if name == "run_agent":
        def forbidden_soul(*args, **kwargs):
            raise AssertionError("SOUL persona loaded despite disabled context")
        module.load_soul_md = forbidden_soul
        builtins.__import__ = original_import
    return module
builtins.__import__ = instrumented_import
runpy.run_path("/worker.py", run_name="__main__")
""".replace("SENTINEL", repr(str(sentinel))).replace(
                "PORT", str(self.server.server_port)
            )
        )
        original = asyncio.create_subprocess_exec

        async def launch(*args, **kwargs):
            args = list(args)
            index = args.index("--chdir")
            args[index:index] = ["--ro-bind", str(wrapper), "/isolation-probe.py"]
            self.assertEqual(args[-1], "/worker.py")
            args[-1] = "/isolation-probe.py"
            return await original(*args, **kwargs)

        with (
            patch.dict(
                os.environ,
                {
                    "DM138_SYNTHETIC_SECRET": "synthetic",
                    "HERMES_KANBAN_TASK": "synthetic",
                },
            ),
            patch.object(asyncio, "create_subprocess_exec", launch),
        ):
            _context, status = self.run_cycle()
        self.assertEqual(status["state"], "completed", status)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(status["reaped"])

    def test_parent_death_leaves_ambiguity_and_no_live_owned_descendants(self):
        import select
        import shutil
        import signal
        import sqlite3
        import subprocess
        import sys

        code = """
import json, time
from tests.test_hermes_review import ActualHermesTests
case = ActualHermesTests()
case.setUp()
from dataclasses import replace
case.instruction = replace(case.instruction, max_cycle_seconds=60)
case.release.clear()
case.approve()
context = case.controller.run_due_once("review-1", 1, case.task)
assert case.received.wait(75)
print(json.dumps(dict(root=str(case.root), source=str(case.runner.source),
                     cycle=context.cycle.cycle_id,
                     pid=case.runner.status(context.cycle.cycle_id)["pid"])),
      flush=True)
time.sleep(60)
"""
        parent = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ.copy(),
        )
        info = None
        try:
            ready, _, _ = select.select([parent.stdout], [], [], 90)
            self.assertTrue(ready, "fixture parent did not reach actual upstream")
            line = parent.stdout.readline()
            self.assertTrue(line, "fixture parent failed")
            info = json.loads(line)
            owned = descendants(info["pid"]) | {info["pid"]}
            self.assertGreater(len(owned), 1)
            parent.kill()
            parent.wait(3)
            limit = time.monotonic() + 18
            while any(process_live(pid) for pid in owned) and time.monotonic() < limit:
                time.sleep(0.05)
            self.assertFalse([pid for pid in owned if process_live(pid)])
            for database, table in (
                ("execution.sqlite", "cycles"),
                ("runtime/hermes.sqlite", "runtime"),
            ):
                with closing(sqlite3.connect(Path(info["root"]) / database)) as db:
                    state = db.execute(
                        f"SELECT state FROM {table} WHERE cycle_id=?", (info["cycle"],)
                    ).fetchone()[0]
                self.assertIn(state, {"intent", "running", "ambiguous"})
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.communicate(timeout=3)
            if info:
                # Only the just-launched owned process group, never historical DB PIDs.
                with suppress(ProcessLookupError):
                    os.killpg(info["pid"], signal.SIGKILL)
                shutil.rmtree(info["root"], ignore_errors=True)
                shutil.rmtree(info["source"], ignore_errors=True)

    def test_cancellation_before_worker_launch_has_zero_provider_and_native_calls(self):
        reached, release = threading.Event(), threading.Event()
        original = self.runner._validate_environment

        def hold():
            reached.set()
            if not release.wait(5):
                raise ExecutionDenied("test barrier timeout")
            original()

        self.runner._validate_environment = hold
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(reached.wait(2))
        self.cancel()
        release.set()
        self.assertTrue(self.runner.wait(context.cycle.cycle_id, 10))
        self.assertEqual((self.calls, self.broker.calls), ([], []))
        self.assertIsNone(self.runner.status(context.cycle.cycle_id)["pid"])
        self.controller.enforce(context)
        self.assertEqual(self.runner.status(context.cycle.cycle_id)["state"], "stopped")
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "stopped"
        )

    def test_signed_periodic_cancel_interrupts_externally_started_owned_cycle(self):
        from daimon_matrix.codex_review import CodexReviewRunner
        from daimon_matrix.human_execution_frontend import HumanTurn
        from daimon_matrix.operator_execution import HumanExecutionOperator

        reached, release = threading.Event(), threading.Event()
        original = self.runner._validate_environment

        def hold():
            reached.set()
            if not release.wait(5):
                raise ExecutionDenied("test barrier timeout")
            original()

        self.runner._validate_environment = hold
        self.instruction = replace(
            self.instruction, mode="periodic", interval=10, max_cycles=3
        )
        other_store = ExecutionStore.create(
            self.root / "unused-codex.sqlite", self.verifier
        )
        other_runner = object.__new__(CodexReviewRunner)
        other_runner.registration = SimpleNamespace(
            binding=("being:test", "body:test", "codex:runner", "codex:session"),
            principal="human:test",
        )
        other_controller = ReviewController(other_store, other_runner, Broker())
        challenge_ids = iter(f"challenge-{index}" for index in range(1, 10))
        operator = HumanExecutionOperator(
            challenge_path=self.root / "challenges.sqlite",
            bindings={
                "codex": (other_store, other_controller),
                "hermes": (self.store, self.controller),
            },
            authenticate=lambda turn: turn.authentication == f"session:{turn.turn_id}",
            signer=lambda _principal, message: self.key.sign(message),
            challenge_id=lambda: next(challenge_ids),
        )

        def turn(label):
            return HumanTurn(
                principal="human:test",
                turn_id=label,
                origin="direct-human",
                authentication=f"session:{label}",
            )

        display = operator.prepare_finite_periodic(
            turn("periodic-prepare"), "hermes", self.instruction, self.task
        )
        status = operator.confirm(
            turn("periodic-confirm"), display["challenge_id"], display
        )
        self.assertEqual(status["state"], "active")
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(reached.wait(2))
        cancel = operator.prepare_cancel(
            turn("cancel-prepare"), "hermes", "review-1", 1
        )
        timer = threading.Timer(0.1, release.set)
        timer.start()
        self.addCleanup(timer.cancel)

        result = operator.confirm_cancel(
            turn("cancel-confirm"), cancel["challenge_id"], cancel
        )
        interrupted_by_confirm = self.runner.wait(context.cycle.cycle_id, 0.2)
        if not interrupted_by_confirm:
            self.controller.enforce(context)

        self.assertEqual(
            result,
            {
                "instruction_id": "review-1",
                "revision": 1,
                "state": "cancelled",
                "interruption": "stopped",
                "cycles": [context.cycle.cycle_id],
            },
        )
        self.assertTrue(interrupted_by_confirm)
        runtime = self.runner.status(context.cycle.cycle_id)
        self.assertIsNone(runtime["pid"])
        self.assertEqual(runtime["state"], "stopped")
        self.assertEqual((self.calls, self.broker.calls), ([], []))
        time.sleep(0.1)
        self.assertEqual((self.calls, self.broker.calls), ([], []))
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")
        with self.assertRaisesRegex(ExecutionDenied, "replay"):
            operator.confirm_cancel(
                turn("cancel-replay"), cancel["challenge_id"], cancel
            )

    def test_unavailable_journal_does_not_prevent_process_stop(self):
        self.instruction = replace(self.instruction, max_cycle_seconds=15)
        self.release.clear()
        self.approve()
        context = self.controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(self.received.wait(32))
        saved = self.store.path.with_suffix(".saved")
        self.store.path.rename(saved)
        try:
            self.assertEqual(
                self.runner.interrupt(context.cycle.cycle_id, 3), "unknown"
            )
            self.assertTrue(self.runner.wait(context.cycle.cycle_id, 5))
            self.assertFalse(self.store.path.exists())
            status = self.runner.status(context.cycle.cycle_id)
            self.assertTrue(status["reaped"])
            self.assertEqual(status["state"], "ambiguous")
        finally:
            saved.rename(self.store.path)
            self.release.set()


def descendants(pid):
    result = set()
    for path in Path(f"/proc/{pid}/task").glob("*/children"):
        with suppress(FileNotFoundError):
            for child in map(int, path.read_text().split()):
                result.add(child)
                result.update(descendants(child))
    return result


def process_live(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def _bad_response_case(kind):
    def test(self):
        response = {
            "id": "synthetic-completion",
            "object": "chat.completion",
            "created": 1,
            "model": "synthetic-review",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": '{"action":"none"}'},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        }
        if kind == "hidden_tool":
            response["choices"][0]["message"]["tool_calls"] = [
                {"function": {"name": "terminal", "arguments": "{}"}}
            ]
        elif kind == "usage":
            response["usage"] = {
                "prompt_tokens": 10,
                "completion_tokens": 2001,
                "total_tokens": 2011,
            }
        elif kind == "model":
            response["model"] = "other"
        elif kind == "scope_override":
            response["choices"][0]["message"]["content"] = (
                '{"scope":1,"text":"x","channel":"other"}'
            )
        elif kind == "duplicate":
            self.response_override = (
                b'{"model":"synthetic-review","model":"synthetic-review"}'
            )
        elif kind == "oversize":
            self.response_override = b'"' + b"x" * 65536 + b'"'
        elif kind == "malformed":
            self.response_override = b"{"
        if self.response_override is None:
            self.response_override = json.dumps(response).encode()
        context, status = self.run_cycle()
        self.assertEqual(status["state"], "ambiguous")
        self.assertTrue(status["reaped"])
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "ambiguous"
        )

    return test


for _case in (
    "hidden_tool",
    "usage",
    "model",
    "scope_override",
    "duplicate",
    "oversize",
    "malformed",
):
    setattr(
        ActualHermesTests,
        "test_actual_provider_rejects_" + _case,
        _bad_response_case(_case),
    )
