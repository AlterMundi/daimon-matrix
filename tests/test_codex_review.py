"""Real pinned App Server tests use ONLY loopback synthetic Responses; no auth."""

import hashlib
import http.server
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


class RegistrationTests(unittest.TestCase):
    def test_registration_requires_external_human_signature_and_exact_existing_body(
        self,
    ):
        from daimon_matrix.codex_review import Registration

        key = Ed25519PrivateKey.generate()
        payload = dict(
            schema="execution/v1/codex-registration",
            principal="human:test",
            store_id="store:test",
            being="being:test",
            embodiment="body:test",
            runner="runner:test",
            session="session:test",
            provider="test",
            model="gpt-5.4",
            endpoint="http://127.0.0.1:1234/v1/responses",
            profile="/tmp/owned-review",
            catalog_sha256="a" * 64,
            expires=200,
            mode="ephemeral-review",
            max_response_bytes=65536,
        )
        verified = Registration.verify(
            payload,
            proof(key, "approve", payload),
            verifier(key),
            lambda value: value["embodiment"] == "body:test",
        )
        self.assertEqual(
            verified.binding, ("being:test", "body:test", "runner:test", "session:test")
        )
        with self.assertRaises(ExecutionDenied):
            Registration.verify(
                payload | {"model": "other"},
                proof(key, "approve", payload),
                verifier(key),
                lambda _: True,
            )
        with self.assertRaises(ExecutionDenied):
            Registration.verify(
                payload, proof(key, "approve", payload), verifier(key), lambda _: False
            )
        with self.assertRaises(ExecutionDenied):
            bad = payload | {"human": True}
            Registration.verify(
                bad, proof(key, "approve", bad), verifier(key), lambda _: True
            )
        with self.assertRaises(ExecutionDenied):
            bad = payload | {"endpoint": "http://public.example/v1/responses"}
            Registration.verify(
                bad, proof(key, "approve", bad), verifier(key), lambda _: True
            )


BINARY = os.environ.get("CODEX_REVIEW_BINARY")
CATALOG = os.environ.get("CODEX_REVIEW_CATALOG")


@unittest.skipUnless(
    BINARY and CATALOG, "set exact pinned binary and public text-only catalog"
)
class PinnedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "review"
        self.home.mkdir(mode=0o700)
        self.key = Ed25519PrivateKey.generate()
        self.verifier = verifier(self.key)
        self.store = ExecutionStore.create(
            self.root / "execution.sqlite", self.verifier
        )
        self.calls = []
        self.request_received = threading.Event()
        self.release_response = threading.Event()
        self.release_response.set()
        self.addCleanup(self.release_response.set)
        self.response_text = '{"action":"none"}'
        self.output_item = None
        self.chunked = False
        self.reasoning = False
        self.status_code = 200
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.calls.append(value)
                owner.request_received.set()
                owner.release_response.wait(5)
                item = owner.output_item or {
                    "id": "msg_test",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": owner.response_text,
                            "annotations": [],
                        }
                    ],
                }
                response = {
                    "id": "resp_test",
                    "status": "completed",
                    "output": (
                        [{"type": "reasoning", "id": "rs_test", "summary": []}]
                        if owner.reasoning
                        else []
                    )
                    + [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                }
                events = [
                    {
                        "type": "response.created",
                        "response": {
                            "id": "resp_test",
                            "status": "in_progress",
                            "output": [],
                        },
                    },
                    {
                        "type": "response.output_item.done",
                        "output_index": 0,
                        "item": item,
                    },
                    {"type": "response.completed", "response": response},
                ]
                raw = "".join(
                    "event: " + e["type"] + "\ndata: " + json.dumps(e) + "\n\n"
                    for e in events
                ).encode()
                self.send_response(owner.status_code)
                self.send_header("Content-Type", "text/event-stream")
                if owner.chunked:
                    self.send_header("Transfer-Encoding", "chunked")
                    raw = f"{len(raw):x}\r\n".encode() + raw + b"\r\n0\r\n\r\n"
                else:
                    self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                with suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(raw)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop_server, self.server, self.thread)
        self.payload = dict(
            schema="execution/v1/codex-registration",
            principal="human:test",
            store_id=self.store.store_id,
            being="being:test",
            embodiment="body:test",
            runner="runner:test",
            session="session:test",
            provider="test",
            model="gpt-5.4",
            endpoint=f"http://127.0.0.1:{self.server.server_port}/v1/responses",
            profile=str(self.home),
            catalog_sha256=hashlib.sha256(Path(CATALOG).read_bytes()).hexdigest(),
            expires=int(time.time()) + 60,
            mode="ephemeral-review",
            max_response_bytes=65536,
        )
        self.task = (
            'Review this synthetic task. Return {"scope":0} '
            "to request the approved inbox."
        )
        now = int(time.time())
        self.instruction = Instruction.from_dict(
            request(
                store_id=self.store.store_id,
                start=now - 1,
                end=now + 30,
                max_cycle_seconds=15,
                max_input_tokens=100000,
                max_output_tokens=200,
                model="gpt-5.4",
                task_sha256=hashlib.sha256(self.task.encode()).hexdigest(),
            )
        )
        self.broker = Broker()

    def stop_server(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(2)

    def runner(self):
        from daimon_matrix.codex_review import CodexReviewRunner

        runner = CodexReviewRunner(
            self.payload,
            proof(self.key, "approve", self.payload),
            self.verifier,
            existing_body=lambda _: True,
            binary=Path(BINARY),
            catalog=Path(CATALOG),
        )
        self.addCleanup(runner.close)
        return runner

    def approve(self):
        self.store.approve(
            self.instruction, proof(self.key, "approve", self.instruction.to_dict())
        )

    def test_cross_principal_instruction_is_denied_before_worker_or_native_calls(self):
        from daimon_matrix.codex_review import CodexReviewRunner
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
        runner = CodexReviewRunner(
            self.payload,
            proof(self.key, "approve", self.payload),
            trusted,
            existing_body=lambda _: True,
            binary=Path(BINARY),
            catalog=Path(CATALOG),
        )
        self.addCleanup(runner.close)
        worker_calls = []
        runner._worker = lambda request, context: worker_calls.append(request.cycle_id)
        self.store.approve(self.instruction, approval)

        with self.assertRaisesRegex(ExecutionDenied, "registered"):
            ReviewController(self.store, runner, self.broker).run_due_once(
                "review-1", 1, self.task
            )

        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM cycles").fetchone()[0], 0)
            self.assertEqual(
                db.execute("SELECT count(*) FROM operations").fetchone()[0], 0
            )
        with closing(sqlite3.connect(runner._state_path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM runtime").fetchone()[0], 0
            )
        self.assertIsNone(runner._thread)
        self.assertEqual(worker_calls, [])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])

    def test_same_principal_instruction_reaches_worker_control_without_effects(self):
        runner = self.runner()
        worker_calls = []
        runner._worker = lambda request, context: worker_calls.append(request.cycle_id)
        self.approve()

        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertIsNotNone(context)
        assert context is not None
        self.assertTrue(runner.wait(context.cycle.cycle_id, 2))
        self.assertEqual(worker_calls, [context.cycle.cycle_id])
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])

    def test_actual_codex_boundary_does_not_observe_native_arrival(self):
        from tests.test_passive_messaging_execution import (
            deliver_store_mirror_without_execution,
        )

        runner = self.runner()
        controller = ReviewController(self.store, runner, self.broker)
        counts = deliver_store_mirror_without_execution(self.root / "passive")
        self.assertIsNone(controller.run_due_once("absent", 1, self.task))
        self.assertEqual(counts, {"stored": 1, "mirrored": 1, "automatic_reply": 0})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.broker.calls, [])

    def test_real_app_server_single_inference_and_scoped_native_receipt(self):
        runner = self.runner()
        controller = ReviewController(self.store, runner, self.broker)
        self.assertIsNone(controller.run_due_once("missing", 1, self.task))
        self.assertEqual(self.calls, [])
        self.approve()
        context = controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(
            runner.wait(context.cycle.cycle_id, 20),
            runner.status(context.cycle.cycle_id),
        )
        status = runner.status(context.cycle.cycle_id)
        self.assertEqual(status["state"], "completed", status)
        self.assertTrue(status["thread_id"])
        self.assertTrue(status["turn_id"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0]["model"], "gpt-5.4")
        self.assertEqual(self.calls[0]["max_output_tokens"], 200)
        self.assertEqual(self.calls[0]["tools"], [])
        self.assertEqual(len(self.broker.calls), 1)
        self.assertEqual(self.broker.calls[0][0], self.instruction.scope[0])
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "completed"
        )
        self.assertIsNone(controller.run_due_once("review-1", 1, self.task))

    def test_hidden_builtin_invocations_never_reach_router_or_broker(self):
        for tool in (
            "apply_patch",
            "view_image",
            "exec_command",
            "spawn_agent",
            "web_search",
            "messaging_send",
        ):
            with self.subTest(tool=tool):
                self.setUp()
                self.output_item = {
                    "id": "fc_bad",
                    "type": "function_call",
                    "call_id": "bad",
                    "name": tool,
                    "arguments": '{"path":"/etc/passwd"}',
                }
                runner = self.runner()
                self.approve()
                context = ReviewController(
                    self.store, runner, self.broker
                ).run_due_once("review-1", 1, self.task)
                self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
                self.assertEqual(
                    runner.status(context.cycle.cycle_id)["state"], "ambiguous"
                )
                self.assertEqual(len(self.calls), 1)
                self.assertEqual(len(self.broker.calls), 1)  # admitted inbox only
                runner.close()

    def test_inactive_cancelled_expired_and_wrong_model_make_zero_requests(self):
        for mode in ("pending", "cancelled", "expired", "model", "body"):
            with self.subTest(mode=mode):
                self.setUp()
                runner = self.runner()
                if mode == "pending":
                    self.store.propose(self.instruction)
                elif mode == "expired":
                    self.instruction = replace(
                        self.instruction,
                        end=int(time.time()) - 1,
                        start=int(time.time()) - 10,
                    )
                    with self.assertRaises(ExecutionDenied):
                        self.approve()
                else:
                    if mode == "model":
                        self.instruction = replace(self.instruction, model="wrong")
                    if mode == "body":
                        self.instruction = replace(self.instruction, embodiment="wrong")
                    self.approve()
                    if mode == "cancelled":
                        self.store.cancel(
                            "review-1",
                            1,
                            proof(
                                self.key,
                                "cancel",
                                self.store.cancellation_payload("review-1", 1),
                                "cancel",
                            ),
                        )
                controller = ReviewController(self.store, runner, self.broker)
                if mode == "model":
                    with self.assertRaises(ExecutionDenied):
                        controller.run_due_once("review-1", 1, self.task)
                else:
                    self.assertIsNone(controller.run_due_once("review-1", 1, self.task))
                self.assertEqual(self.calls, [])
                self.assertEqual(self.broker.calls, [])
                runner.close()

    def test_config_drift_fails_before_startup(self):
        runner = self.runner()
        self.approve()
        (self.home / "config.toml").write_text('model="wrong"')
        with self.assertRaises(ExecutionDenied):
            ReviewController(self.store, runner, self.broker).run_due_once(
                "review-1", 1, self.task
            )
        self.assertEqual(self.calls, [])

    def test_input_output_and_destination_budgets_are_real(self):
        for mode in ("input", "output", "destination"):
            with self.subTest(mode=mode):
                self.setUp()
                if mode == "input":
                    self.instruction = replace(self.instruction, max_input_tokens=1)
                elif mode == "output":
                    self.response_text = "x" * 201
                else:
                    self.response_text = '{"scope":0,"channel":"not-approved"}'
                runner = self.runner()
                self.approve()
                context = ReviewController(
                    self.store, runner, self.broker
                ).run_due_once("review-1", 1, self.task)
                self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
                self.assertEqual(
                    runner.status(context.cycle.cycle_id)["state"], "ambiguous"
                )
                self.assertEqual(len(self.calls), 0 if mode == "input" else 1)
                self.assertEqual(len(self.broker.calls), 1)  # no model-selected effects
                runner.close()

    def test_restart_cannot_retry_ambiguous_turn(self):
        self.output_item = {
            "id": "bad",
            "type": "function_call",
            "call_id": "bad",
            "name": "exec_command",
            "arguments": "{}",
        }
        runner = self.runner()
        self.approve()
        controller = ReviewController(self.store, runner, self.broker)
        context = controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
        saved = runner.status(context.cycle.cycle_id)
        runner.close()
        reopened = self.runner()
        self.assertEqual(reopened.status(context.cycle.cycle_id), saved)
        self.assertEqual(reopened.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.assertIsNone(
            ReviewController(self.store, reopened, self.broker).run_due_once(
                "review-1", 1, self.task
            )
        )
        self.assertEqual(len(self.calls), 1)

    def test_inbox_is_mediated_before_inference_and_reply_uses_exact_scope(self):
        from daimon_matrix.execution_instruction import Scope

        self.instruction = replace(
            self.instruction,
            scope=(
                self.instruction.scope[0],
                Scope("channel:test", "thread:test", "messaging_reply", "reply"),
            ),
        )
        self.response_text = '{"scope":1,"text":"bounded reply"}'
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
        self.assertEqual(runner.status(context.cycle.cycle_id)["state"], "completed")
        self.assertEqual(
            [call[0] for call in self.broker.calls], list(self.instruction.scope)
        )
        self.assertIn("technical-only", json.dumps(self.calls[0]["input"]))
        self.assertEqual(self.broker.calls[1][1], {"text": "bounded reply"})

    def test_cancel_inflight_stops_local_process_but_remote_remains_unknown(self):
        self.release_response.clear()
        runner = self.runner()
        self.approve()
        controller = ReviewController(self.store, runner, self.broker)
        context = controller.run_due_once("review-1", 1, self.task)
        self.assertTrue(self.request_received.wait(5))
        self.store.cancel(
            "review-1",
            1,
            proof(
                self.key,
                "cancel",
                self.store.cancellation_payload("review-1", 1),
                "cancel",
            ),
        )
        controller.enforce(context)
        self.assertTrue(runner.wait(context.cycle.cycle_id, 2))
        self.assertEqual(runner.interrupt(context.cycle.cycle_id, 1), "unknown")
        self.assertEqual(
            self.store.cycle_status(context.cycle.cycle_id)["state"], "ambiguous"
        )
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.broker.calls), 1)  # preflight inbox only
        self.release_response.set()

    def test_signed_review_now_cancel_interrupts_owned_inflight_cycle(self):
        from daimon_matrix.hermes_review import HermesReviewRunner
        from daimon_matrix.human_execution_frontend import HumanTurn
        from daimon_matrix.operator_execution import HumanExecutionOperator

        self.release_response.clear()
        runner = self.runner()
        controller = ReviewController(self.store, runner, self.broker)
        other_store = ExecutionStore.create(
            self.root / "unused-hermes.sqlite", self.verifier
        )
        other_runner = object.__new__(HermesReviewRunner)
        other_runner.registration = SimpleNamespace(
            binding=("being:test", "body:test", "hermes:runner", "hermes:session"),
            principal="human:test",
        )
        other_controller = ReviewController(other_store, other_runner, Broker())
        challenge_ids = iter(f"challenge-{index}" for index in range(1, 10))
        operator = HumanExecutionOperator(
            challenge_path=self.root / "challenges.sqlite",
            bindings={
                "codex": (self.store, controller),
                "hermes": (other_store, other_controller),
            },
            authenticate=lambda turn: turn.authentication == f"session:{turn.turn_id}",
            signer=lambda _principal, message: self.key.sign(message),
            challenge_id=lambda: next(challenge_ids),
        )
        self.instruction = replace(
            self.instruction, mode="manual", interval=None, max_cycles=1
        )

        def turn(label):
            return HumanTurn(
                principal="human:test",
                turn_id=label,
                origin="direct-human",
                authentication=f"session:{label}",
            )

        display = operator.prepare_review_now(
            turn("review-prepare"), "codex", self.instruction, self.task
        )
        context = operator.confirm(
            turn("review-confirm"), display["challenge_id"], display
        )
        self.assertTrue(self.request_received.wait(5))
        cancel = operator.prepare_cancel(turn("cancel-prepare"), "codex", "review-1", 1)

        result = operator.confirm_cancel(
            turn("cancel-confirm"), cancel["challenge_id"], cancel
        )
        interrupted_by_confirm = runner.wait(context.cycle.cycle_id, 0.2)
        if not interrupted_by_confirm:
            controller.enforce(context)

        self.assertEqual(
            result,
            {
                "instruction_id": "review-1",
                "revision": 1,
                "state": "cancelled",
                "interruption": "unknown",
                "cycles": [context.cycle.cycle_id],
            },
        )
        self.assertTrue(interrupted_by_confirm)
        runtime = runner.status(context.cycle.cycle_id)
        self.assertEqual(runtime["state"], "ambiguous")
        pid = runtime["pid"]
        if pid is not None:
            proc = Path(f"/proc/{pid}/stat")
            self.assertTrue(not proc.exists() or proc.read_text().split()[2] == "Z")
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))
        self.release_response.set()
        time.sleep(0.1)
        self.assertEqual((len(self.calls), len(self.broker.calls)), (1, 1))
        self.assertEqual(self.store.status("review-1", 1)["state"], "cancelled")
        with self.assertRaisesRegex(ExecutionDenied, "replay"):
            operator.confirm_cancel(
                turn("cancel-replay"), cancel["challenge_id"], cancel
            )

    def test_absolute_deadline_supervisor_stops_hanging_provider(self):
        self.release_response.clear()
        self.instruction = replace(self.instruction, max_cycle_seconds=2)
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(runner.wait(context.cycle.cycle_id, 5))
        self.assertEqual(runner.status(context.cycle.cycle_id)["state"], "ambiguous")
        self.assertEqual(len(self.broker.calls), 1)
        self.release_response.set()

    def test_process_deadline_is_independent_of_blocked_journal(self):
        import sqlite3

        self.release_response.clear()
        self.instruction = replace(self.instruction, max_cycle_seconds=3)
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(self.request_received.wait(5))
        pid = runner.status(context.cycle.cycle_id)["pid"]
        db = sqlite3.connect(self.store.path, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            time.sleep(3.2)
            # The OS deadline must kill the runtime even while Python/SQLite is blocked.
            proc = Path(f"/proc/{pid}/stat")
            self.assertTrue(not proc.exists() or proc.read_text().split()[2] == "Z")
        finally:
            db.rollback()
            db.close()
            self.release_response.set()
        self.assertTrue(runner.wait(context.cycle.cycle_id, 3))

    def test_runtime_and_registration_are_public_schema_valid(self):
        from jsonschema import Draft202012Validator

        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/execution/v1/instruction.schema.json"
            ).read_text()
        )
        definition = schema["$defs"]["codex_registration"]
        Draft202012Validator(definition).validate(self.payload)
        for change in ({"mode": "arrival"}, {"human": True}, {"expires": True}):
            self.assertFalse(
                Draft202012Validator(definition).is_valid(self.payload | change)
            )

    def test_chunked_responses_transport_is_supported(self):
        self.chunked = True
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
        self.assertEqual(runner.status(context.cycle.cycle_id)["state"], "completed")
        self.assertEqual(len(self.calls), 1)

    def test_provider_failure_never_retries_or_resumes_inference(self):
        self.status_code = 503
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
        self.assertEqual(runner.status(context.cycle.cycle_id)["state"], "ambiguous")
        self.assertEqual(len(self.calls), 1)

    def test_reasoning_is_not_a_tool_and_is_not_exposed_to_native_broker(self):
        self.reasoning = True
        runner = self.runner()
        self.approve()
        context = ReviewController(self.store, runner, self.broker).run_due_once(
            "review-1", 1, self.task
        )
        self.assertTrue(runner.wait(context.cycle.cycle_id, 10))
        self.assertEqual(runner.status(context.cycle.cycle_id)["state"], "completed")
        self.assertEqual(len(self.broker.calls), 1)
