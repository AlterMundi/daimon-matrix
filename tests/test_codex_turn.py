"""Bounded inference transport through real subprocess pipes, without a provider."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import tests.test_codex_0155_body as profile_fixture
from daimon_matrix import codex_body as body
from daimon_matrix import codex_matrix_binding as bridge
from daimon_matrix.codex_body import (
    MAX_DOCUMENT_BYTES,
    AppServerProcess,
    CodexBodyError,
)


class BoundedTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="codex-turn-io-")
        self.root = Path(self.directory.name)
        self.transports: list[AppServerProcess] = []

    def tearDown(self) -> None:
        for transport in self.transports:
            transport.close()
        self.directory.cleanup()

    def transport(self, script: str) -> AppServerProcess:
        # Only the I/O seam is synthetic: production framing, writes, deadlines,
        # correlation, notification capture and shutdown execute unchanged.
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", script, str(self.root / "accepted")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        transport = AppServerProcess.__new__(AppServerProcess)
        transport.process = process
        transport._stdin = process.stdin
        transport._stdout = process.stdout
        os.set_blocking(transport._stdout.fileno(), False)
        transport._automatic_hooks = False
        transport._profile_lock = None
        transport._read_buffer = bytearray()
        transport._next_id = 1
        transport._pending = set()
        transport._seen = set()
        transport._configuration_request_id = None
        self.transports.append(transport)
        return transport

    def test_notifications_before_ack_are_retained_in_order(self) -> None:
        transport = self.transport(
            "import json,sys\n"
            "request=json.loads(sys.stdin.readline())\n"
            "for delta in ['first','second']:\n"
            " print(json.dumps({'method':'item/agentMessage/delta','params':"
            "{'threadId':'thread-a','turnId':'turn-a','itemId':'item-a','delta':delta}}),flush=True)\n"
            "print(json.dumps({'id':request['id'],'result':{'turn':{'id':'turn-a','status':'inProgress','items':[]}}}),flush=True)\n"
        )
        result, captured = transport.request_bounded(
            "turn/start",
            {"threadId": "thread-a", "input": []},
            deadline=time.monotonic() + 2,
        )
        self.assertEqual(result["turn"]["id"], "turn-a")
        self.assertEqual(
            [row["params"]["delta"] for row in captured], ["first", "second"]
        )
        self.assertTrue(os.get_blocking(transport._stdin.fileno()))

    def test_native_text_and_finite_tool_numbers_keep_vendor_encoding(self) -> None:
        transport = self.transport(
            "import json,sys\n"
            "request=json.loads(sys.stdin.readline())\n"
            "assert request['params']['input'][0]['text']=='e\\u0301'\n"
            "result={'turn':{'id':'turn-a','status':'completed','items':"
            "[{'id':'tool-a','type':'mcpToolCall','arguments':{'fraction':.25}}]}}\n"
            "print(json.dumps({'id':request['id'],'result':result}),flush=True)\n"
        )
        result, _ = transport.request_bounded(
            "turn/start",
            {
                "threadId": "thread-a",
                "input": [{"type": "text", "text": "e\u0301", "text_elements": []}],
            },
            deadline=time.monotonic() + 2,
        )
        self.assertEqual(result["turn"]["items"][0]["arguments"]["fraction"], 0.25)
        with self.assertRaises(CodexBodyError):
            body._json_load(b'{"signed":0.25}', "signed_fixture_rejected")
        with self.assertRaises(CodexBodyError):
            body._json_load(b'{"signed":"e\\u0301"}', "signed_fixture_rejected")

    def test_nonfinite_vendor_response_refuses_without_resubmission(self) -> None:
        transport = self.transport(
            "import json,sys\nrequest=json.loads(sys.stdin.readline())\n"
            "print(json.dumps({'id':request['id'],'result':{'opaque':float('nan')}}),flush=True)\n"
        )
        with self.assertRaises(CodexBodyError) as caught:
            transport.request_bounded("turn/start", {}, deadline=time.monotonic() + 2)
        self.assertEqual(caught.exception.code, "app_server_frame_invalid")
        self.assertEqual(transport._next_id, 2)

    def test_trickling_notifications_cannot_reset_deadline_or_resubmit(self) -> None:
        transport = self.transport(
            "import json,sys,time\nfrom pathlib import Path\n"
            "json.loads(sys.stdin.readline())\n"
            "Path(sys.argv[1]).write_text('one accepted request')\n"
            "for index in range(20):\n"
            " print(json.dumps({'method':'warning','params':"
            "{'message':'synthetic warning'}}),flush=True)\n"
            " time.sleep(.03)\n"
        )
        started = time.monotonic()
        with self.assertRaises(CodexBodyError) as caught:
            transport.request_bounded(
                "turn/start",
                {"threadId": "thread-a", "input": []},
                deadline=started + 0.15,
            )
        self.assertEqual(caught.exception.code, "app_server_timeout")
        self.assertLess(time.monotonic() - started, 0.6)
        self.assertEqual((self.root / "accepted").read_text(), "one accepted request")
        self.assertEqual(transport._next_id, 2)

    def test_stalled_child_write_uses_the_same_deadline(self) -> None:
        transport = self.transport("import time;time.sleep(1)")
        started = time.monotonic()
        with self.assertRaises(CodexBodyError) as caught:
            transport.request_bounded(
                "turn/start",
                {"input": "x" * (MAX_DOCUMENT_BYTES // 2)},
                deadline=started + 0.1,
            )
        self.assertEqual(caught.exception.code, "app_server_timeout")
        self.assertLess(time.monotonic() - started, 0.6)
        self.assertTrue(os.get_blocking(transport._stdin.fileno()))

    def test_pre_ack_notification_flood_is_bounded(self) -> None:
        transport = self.transport(
            "import json,sys\njson.loads(sys.stdin.readline())\n"
            "for index in range(65):\n"
            " print(json.dumps({'method':'warning','params':"
            "{'message':'synthetic warning'}}),flush=True)\n"
        )
        with self.assertRaises(CodexBodyError) as caught:
            transport.request_bounded("turn/start", {}, deadline=time.monotonic() + 2)
        self.assertEqual(caught.exception.code, "app_server_notifications_overflow")


class ExplicitTurnDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="dm-explicit-turn-fd-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def descriptor(self, data: bytes, *, mode: int = 0o600) -> int:
        path = self.root / str(len(list(self.root.iterdir())))
        path.write_bytes(data)
        path.chmod(mode)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_input_reads_selected_bytes_without_moving_offset(self) -> None:
        descriptor = self.descriptor("Pregunta sintética\n".encode())
        os.lseek(descriptor, 3, os.SEEK_SET)
        self.assertEqual(
            body.read_native_turn_input(descriptor), "Pregunta sintética\n"
        )
        self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), 3)

    def test_provider_token_allows_only_explicit_private_value(self) -> None:
        descriptor = self.descriptor(b"synthetic-provider-value\n")
        self.assertEqual(
            body.read_native_provider_token(descriptor), "synthetic-provider-value"
        )
        for value in (b"private value with whitespace", b"PRIVATE_VALUE\x00", b"\xff"):
            with self.subTest(value_type="invalid"):
                with self.assertRaises(CodexBodyError) as caught:
                    body.read_native_provider_token(self.descriptor(value))
                self.assertNotIn("PRIVATE_VALUE", str(caught.exception))

    def test_shared_hardlinked_and_writable_descriptors_refuse(self) -> None:
        shared = self.descriptor(b"synthetic", mode=0o640)
        with self.assertRaises(CodexBodyError):
            body.read_native_turn_input(shared)
        linked = self.descriptor(b"synthetic")
        path = self.root / "1"
        os.link(path, self.root / "alias")
        with self.assertRaises(CodexBodyError):
            body.read_native_provider_token(linked)
        writable = os.open(path, os.O_RDWR)
        self.addCleanup(os.close, writable)
        with self.assertRaises(CodexBodyError):
            body.read_native_turn_input(writable)

    def test_empty_oversized_and_invalid_utf8_inputs_refuse(self) -> None:
        for data in (b"", b"x" * 4097, b"\xff"):
            with self.subTest(size=len(data)), self.assertRaises(CodexBodyError):
                body.read_native_turn_input(self.descriptor(data))


class TurnIntentTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = profile_fixture.SuccessorProfileTests(methodName="runTest")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.create()
        self.plan = fixture.plan
        self.now = fixture.now
        self.request_id = "11111111-1111-4111-8111-111111111111"
        self.journal = body.RuntimeHandleJournal(
            self.plan.profile_root / "runtime-handles.jsonl", plan=self.plan
        )
        core = {
            key: fixture.bootstrap[key]
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
            )
        }
        core.update(
            thread_id="thread-fixture",
            session_tree_id="session-fixture",
            turn_id=None,
            state="active",
            observed_at_ms=self.now,
        )
        self.active = self.journal.append(core)

    def reserve(self, **changes: Any) -> dict[str, Any]:
        arguments: dict[str, Any] = dict(
            request_id=self.request_id,
            input_text="Private synthetic input",
            active_handle=self.active,
            timeout_seconds=30,
            max_response_bytes=4096,
            retain_until_ms=self.now + 60_000,
            at_ms=self.now,
        )
        arguments.update(changes)
        return body.prepare_turn_intent(self.plan, **arguments)

    def test_reservation_preserves_handle_and_excludes_prompt(self) -> None:
        before = self.journal.path.read_bytes()
        intent = self.reserve()
        path = self.plan.profile_root / "turn-requests" / (self.request_id + ".json")
        self.assertNotIn(b"Private synthetic input", path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(body.read_turn_intent(self.plan, self.request_id), intent)
        self.assertEqual(self.journal.path.read_bytes(), before)

    def test_repeated_request_never_replaces_even_torn_intent(self) -> None:
        self.reserve()
        path = self.plan.profile_root / "turn-requests" / (self.request_id + ".json")
        original = path.read_bytes()
        for replacement in (original, b'{"incomplete":'):
            path.write_bytes(replacement)
            with self.assertRaises(CodexBodyError) as caught:
                self.reserve(input_text="Different input")
            self.assertEqual(caught.exception.code, "turn_request_already_reserved")
            self.assertEqual(path.read_bytes(), replacement)

    def test_invalid_selection_refuses_before_reservation(self) -> None:
        for changes in (
            {"request_id": "../request"},
            {"timeout_seconds": True},
            {"max_response_bytes": 65537},
            {"input_text": ""},
            {"retain_until_ms": self.now},
            {"input_text": "x" * 4097},
            {"input_text": "\ud800"},
        ):
            with self.subTest(changes=changes), self.assertRaises(CodexBodyError):
                self.reserve(**changes)
        self.assertFalse((self.plan.profile_root / "turn-requests").exists())

    def test_stale_or_pending_handle_refuses_before_reservation(self) -> None:
        core = {
            key: value
            for key, value in self.active.items()
            if key
            not in {
                "handle_id",
                "generation",
                "previous_handle_id",
                *body._TURN_BINDING_FIELDS,
            }
        }
        core.update(
            {
                key: self.active[key]
                for key in (
                    "being_ref",
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "matrix_session_id",
                )
            }
        )
        core["state"] = "resuming"
        pending = self.journal.append(core)
        for handle in (self.active, pending):
            with self.assertRaises(CodexBodyError):
                self.reserve(active_handle=handle)
        self.assertFalse((self.plan.profile_root / "turn-requests").exists())

    def test_substituted_intent_is_refused_without_rewriting(self) -> None:
        self.reserve()
        path = self.plan.profile_root / "turn-requests" / (self.request_id + ".json")
        value = json.loads(path.read_text())
        value["input_sha256"] = "f" * 64
        path.write_text(json.dumps(value))
        before = path.read_bytes()
        with self.assertRaises(CodexBodyError):
            body.read_turn_intent(self.plan, self.request_id)
        self.assertEqual(path.read_bytes(), before)

    def test_aliased_intent_directory_refuses_without_source_effects(self) -> None:
        target = self.plan.workspace / "alias-target"
        target.mkdir(mode=0o700)
        (self.plan.profile_root / "turn-requests").symlink_to(
            target, target_is_directory=True
        )
        with self.assertRaises(CodexBodyError):
            self.reserve()
        self.assertEqual(list(target.iterdir()), [])


class TurnControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = TurnIntentTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.io = BoundedTransportTests(methodName="runTest")
        self.io.setUp()
        self.addCleanup(self.io.tearDown)

    def adapter(self, script: str) -> body.CodexBodyAdapter:
        fixture = self.fixture
        transport = self.io.transport(script)

        def presence(binding: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
            return {
                key: binding[key]
                for key in (
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "matrix_session_id",
                    "matrix_high_water",
                )
            } | {"state": "active", "expires_at_ms": at_ms + 60_000}

        adapter = body.CodexBodyAdapter(
            fixture.plan,
            transport,
            presence,
            fixture.journal,
            clock=lambda: fixture.now,
        )
        adapter.initialized = True
        return adapter

    def run_turn(self, adapter: body.CodexBodyAdapter) -> dict[str, Any]:
        return adapter.run_turn(
            "Synthetic one input",
            request_id=self.fixture.request_id,
            timeout_seconds=1,
            max_response_bytes=4096,
            retain_until_ms=self.fixture.now + 60_000,
        )

    def script(
        self,
        *,
        status: str = "completed",
        foreign: bool = False,
        early: bool = False,
        notifications: list[dict[str, Any]] | None = None,
        answer: str | None = None,
        collide_result: bool = False,
    ) -> str:
        path = self.fixture.plan.profile_root
        request_path = path / "turn-requests" / (self.fixture.request_id + ".json")
        result_path = path / "turn-results" / (self.fixture.request_id + ".json")
        terminal: dict[str, Any] = {
            "method": "turn/completed",
            "params": {
                "threadId": "foreign" if foreign else "thread-fixture",
                "turn": {
                    "id": "turn-a",
                    "items": [],
                    "status": status,
                    "error": None
                    if status == "completed"
                    else {"message": "PRIVATE_PROVIDER_TOKEN"},
                },
            },
        }
        if answer is not None:
            terminal["params"]["turn"]["items"] = [
                {"id": "answer-a", "type": "agentMessage", "text": answer}
            ]
        return (
            "import json,sys\nfrom pathlib import Path\n"
            "request=json.loads(sys.stdin.readline())\n"
            f"assert Path({str(request_path)!r}).is_file()\n"
            f"journal=Path({str(path / 'runtime-handles.jsonl')!r})\n"
            "assert json.loads(journal.read_text().splitlines()[-1])"
            "['state']=='turning'\n"
            "assert len(request['params']['input'])==1\n"
            "Path(sys.argv[1]).write_text('one')\n"
            + (
                f"Path({str(result_path)!r}).write_text('late conflicting result')\n"
                if collide_result
                else ""
            )
            + "".join(
                f"print(json.dumps({event!r}),flush=True)\n"
                for event in (notifications or [])
            )
            + (f"print(json.dumps({terminal!r}),flush=True)\n" if early else "")
            + "reply={'id':request['id'],'result':{'turn':"
            "{'id':'turn-a','items':[],'status':'inProgress'}}}\n"
            "print(json.dumps(reply),flush=True)\n"
            + ("" if early else f"print(json.dumps({terminal!r}),flush=True)\n")
        )

    def test_success_keeps_one_input_and_correlated_durable_handle(self) -> None:
        adapter = self.adapter(self.script(early=True))
        result = self.run_turn(adapter)
        self.assertEqual(result["turn_status"], "completed")
        self.assertEqual(result["handle"]["turn_id"], "turn-a")
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "active")
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        self.assertEqual((self.io.root / "accepted").read_text(), "one")
        saved = body.read_native_turn_result(self.fixture.plan, self.fixture.request_id)
        self.assertEqual(saved["result_id"], result["result_id"])
        path = (
            self.fixture.plan.profile_root
            / "turn-results"
            / (self.fixture.request_id + ".json")
        )
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_preexisting_result_refuses_before_input(self) -> None:
        directory = self.fixture.plan.profile_root / "turn-results"
        directory.mkdir(mode=0o700)
        path = directory / (self.fixture.request_id + ".json")
        path.write_bytes(b"torn preexisting result")
        path.chmod(0o600)
        adapter = self.adapter(self.script())
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        self.assertEqual(path.read_bytes(), b"torn preexisting result")
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "active")
        self.assertFalse((self.io.root / "accepted").exists())

    def test_late_result_collision_keeps_pending_without_replay(self) -> None:
        adapter = self.adapter(self.script(collide_result=True))
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        path = (
            self.fixture.plan.profile_root
            / "turn-results"
            / (self.fixture.request_id + ".json")
        )
        self.assertEqual(path.read_text(), "late conflicting result")
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "turning")
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        self.assertEqual((self.io.root / "accepted").read_text(), "one")

    def test_changed_result_refuses_without_mutating_journal(self) -> None:
        self.run_turn(self.adapter(self.script(answer="Synthetic private answer")))
        before = self.fixture.journal.path.read_bytes()
        path = (
            self.fixture.plan.profile_root
            / "turn-results"
            / (self.fixture.request_id + ".json")
        )
        value = json.loads(path.read_bytes())
        value["native_turn"]["items"][0]["text"] = "Substituted answer"
        path.write_text(json.dumps(value))
        with self.assertRaises(CodexBodyError):
            body.read_native_turn_result(self.fixture.plan, self.fixture.request_id)
        self.assertEqual(self.fixture.journal.path.read_bytes(), before)

    def test_private_result_preserves_non_normalized_native_text(self) -> None:
        self.run_turn(self.adapter(self.script(answer="e\u0301")))
        saved = body.read_native_turn_result(self.fixture.plan, self.fixture.request_id)
        self.assertEqual(saved["native_turn"]["items"][0]["text"], "e\u0301")

    def test_failed_native_turn_is_not_success_and_error_is_redacted(self) -> None:
        result = self.run_turn(self.adapter(self.script(status="failed")))
        self.assertEqual(result["turn_status"], "failed")
        self.assertNotIn("PRIVATE_PROVIDER_TOKEN", json.dumps(result))

    def test_foreign_terminal_keeps_pending_and_forbids_new_input(self) -> None:
        adapter = self.adapter(self.script(foreign=True))
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        before = self.fixture.journal.path.read_bytes()
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "turning")
        with self.assertRaises(CodexBodyError):
            self.run_turn(adapter)
        self.assertEqual(self.fixture.journal.path.read_bytes(), before)

    def test_native_reasoning_and_usage_before_ack_are_correlated(self) -> None:
        common = {"threadId": "thread-fixture", "turnId": "turn-a"}
        counts = dict.fromkeys(
            (
                "cachedInputTokens",
                "inputTokens",
                "outputTokens",
                "reasoningOutputTokens",
                "totalTokens",
            ),
            1,
        )
        events = [
            {
                "method": "item/reasoning/summaryPartAdded",
                "params": {
                    **common,
                    "itemId": "reason-a",
                    "summaryIndex": 0,
                },
            },
            {
                "method": "item/reasoning/textDelta",
                "params": {
                    **common,
                    "itemId": "reason-a",
                    "contentIndex": 0,
                    "delta": "Synthetic reasoning",
                },
            },
            {
                "method": "thread/tokenUsage/updated",
                "params": {
                    **common,
                    "tokenUsage": {"last": counts, "total": counts},
                },
            },
            {
                "method": "item/completed",
                "params": {
                    **common,
                    "completedAtMs": 1,
                    "item": {
                        "id": "answer-a",
                        "type": "agentMessage",
                        "text": "Synthetic answer",
                    },
                },
            },
        ]
        result = self.run_turn(self.adapter(self.script(notifications=events)))
        self.assertEqual(result["turn_status"], "completed")
        self.assertEqual((self.io.root / "accepted").read_text(), "one")

    def test_malformed_item_keeps_turn_pending(self) -> None:
        event = {
            "method": "item/completed",
            "params": {
                "threadId": "thread-fixture",
                "turnId": "turn-a",
                "completedAtMs": 1,
                "item": {"id": "answer-a", "type": "agentMessage", "text": []},
            },
        }
        with self.assertRaises(CodexBodyError) as caught:
            self.run_turn(self.adapter(self.script(notifications=[event])))
        self.assertEqual(caught.exception.code, "codex_turn_item_rejected")
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "turning")

    def test_foreign_reasoning_before_ack_keeps_pending(self) -> None:
        event = {
            "method": "item/reasoning/textDelta",
            "params": {
                "threadId": "foreign",
                "turnId": "turn-a",
                "itemId": "reason-a",
                "contentIndex": 0,
                "delta": "Unrelated reasoning",
            },
        }
        with self.assertRaises(CodexBodyError) as caught:
            self.run_turn(self.adapter(self.script(notifications=[event])))
        self.assertEqual(caught.exception.code, "codex_turn_thread_drift")
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "turning")

    def test_reasoning_extension_does_not_widen_historical_notifications(self) -> None:
        event = {
            "method": "item/reasoning/textDelta",
            "params": {
                "threadId": "thread-fixture",
                "turnId": "turn-a",
                "itemId": "reason-a",
                "contentIndex": 0,
                "delta": "Synthetic reasoning",
            },
        }
        with self.assertRaises(CodexBodyError) as caught:
            body._validate_notification(event)
        self.assertEqual(caught.exception.code, "app_server_protocol_drift")

    def test_lost_ack_retains_intent_and_pending_native_ids(self) -> None:
        adapter = self.adapter("import sys;sys.stdin.readline()")
        with self.assertRaises(CodexBodyError) as caught:
            self.run_turn(adapter)
        self.assertFalse(caught.exception.retryable)
        self.assertEqual(self.fixture.journal.load()[-1]["state"], "turning")
        self.assertEqual(
            body.read_turn_intent(self.fixture.plan, self.fixture.request_id)[
                "request_id"
            ],
            self.fixture.request_id,
        )
        report = body.describe_native_launch_state(self.fixture.plan)
        self.assertEqual(report["outcome"], "unknown-turn-outcome")
        self.assertFalse(report["automatic_retry_allowed"])


class TurnRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = TurnControllerTests(methodName="runTest")
        self.controller.setUp()
        self.addCleanup(self.controller.doCleanups)
        self.fixture = self.controller.fixture

    def pending(self, *, known: bool = True, baseline: str | None = None) -> None:
        core = {
            name: self.fixture.active[name]
            for name in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
                "thread_id",
                "session_tree_id",
                "turn_id",
                "state",
                "observed_at_ms",
            )
        }
        if baseline is not None:
            self.fixture.active = self.fixture.journal.append(
                {**core, "turn_id": baseline}
            )
        self.fixture.reserve(timeout_seconds=1)
        self.fixture.journal.append(
            {**core, "turn_id": "turn-a" if known else None, "state": "turning"}
        )

    def turn(self, **changes: Any) -> dict[str, Any]:
        return {
            "id": "turn-a",
            "status": "completed",
            "itemsView": "full",
            "error": None,
            "items": [
                {
                    "id": "input-a",
                    "type": "userMessage",
                    "content": [{"type": "text", "text": "Private synthetic input"}],
                },
                {"id": "answer-a", "type": "agentMessage", "text": "Private answer"},
            ],
            **changes,
        }

    def script(
        self,
        *,
        turn: dict[str, Any] | None = None,
        thread_changes: dict[str, Any] | None = None,
        cursor: str | None = None,
        preceding: str | None = None,
        notification: dict[str, Any] | None = None,
    ) -> str:
        source = profile_fixture.SuccessorProfileTests(methodName="runTest")
        source.plan = self.fixture.plan
        source.workspace = self.fixture.plan.workspace
        metadata = {"thread": source.thread_response()["thread"]}
        metadata["thread"].update(id="thread-fixture", sessionId="session-fixture")
        metadata["thread"].update(
            createdAt=1,
            updatedAt=2,
            cwd=str(self.fixture.plan.workspace),
            ephemeral=False,
            preview="",
            projectId=None,
            source="appServer",
            status={"type": "idle"},
            turns=[],
            canAcceptDirectInput=True,
            daybreakEnabled=False,
            environments=[],
            extra=None,
        )
        metadata["thread"].update(thread_changes or {})
        calls = [
            (
                "thread/read",
                {"threadId": "thread-fixture", "includeTurns": False},
                metadata,
            ),
            (
                "thread/turns/list",
                {
                    "threadId": "thread-fixture",
                    "limit": 1,
                    "sortDirection": "desc",
                    "itemsView": "full",
                    "cursor": None,
                },
                {
                    "data": [turn if turn is not None else self.turn()],
                    "nextCursor": cursor,
                },
            ),
        ]
        if preceding is not None:
            calls.append(
                (
                    "thread/turns/list",
                    {
                        "threadId": "thread-fixture",
                        "limit": 1,
                        "sortDirection": "desc",
                        "itemsView": "notLoaded",
                        "cursor": cursor,
                    },
                    {
                        "data": [
                            {
                                "id": preceding,
                                "items": [],
                                "status": "completed",
                                "error": None,
                                "itemsView": "notLoaded",
                            }
                        ],
                        "nextCursor": None,
                    },
                )
            )
        script = "import json,sys\nfrom pathlib import Path\nmethods=[]\n"
        for index, (method, params, result) in enumerate(calls):
            script += (
                "request=json.loads(sys.stdin.readline())\n"
                f"assert request['method']=={method!r}\n"
                f"assert request['params']=={params!r}\n"
                "methods.append(request['method'])\n"
            )
            if index == 0 and notification is not None:
                script += f"print(json.dumps({notification!r}),flush=True)\n"
            reply = {"result": result}
            script += (
                f"print(json.dumps({reply!r} | {{'id':request['id']}}),flush=True)\n"
            )
        return script + "Path(sys.argv[1]).write_text(json.dumps(methods))\n"

    def recover(self, **changes: Any) -> dict[str, Any]:
        adapter = self.controller.adapter(self.script(**changes))
        return adapter.recover_turn(request_id=self.fixture.request_id)

    def test_known_id_reconciles_terminal_result_without_model_input(self) -> None:
        self.pending()
        result = self.recover()
        self.assertEqual(result["model_inputs"], 0)
        self.assertEqual(result["handle"]["state"], "active")
        saved = body.read_native_turn_result(
            self.fixture.plan, self.fixture.request_id, recovered=True
        )
        self.assertEqual(saved["result_id"], result["result_id"])
        adapter = self.controller.adapter("raise AssertionError('no further RPC')\n")
        with self.assertRaises(CodexBodyError) as caught:
            adapter.recover_turn(request_id=self.fixture.request_id)
        self.assertEqual(caught.exception.code, "codex_turn_recovery_not_pending")

    def test_lost_ack_proves_first_turn_or_direct_successor(self) -> None:
        self.pending(known=False)
        result = self.recover()
        self.assertEqual(result["handle"]["turn_id"], "turn-a")
        self.assertEqual(
            [row["state"] for row in self.fixture.journal.load()],
            ["active", "turning", "turning", "active"],
        )

    def test_lost_ack_checks_only_previous_id_without_loading_old_items(self) -> None:
        self.pending(known=False, baseline="turn-before")
        result = self.recover(cursor="synthetic-cursor", preceding="turn-before")
        self.assertEqual(result["model_inputs"], 0)

    def test_ambiguous_lost_ack_preserves_pending_bytes(self) -> None:
        self.pending(known=False, baseline="turn-before")
        before = self.fixture.journal.path.read_bytes()
        for params in ({}, {"cursor": "cursor", "preceding": "foreign"}):
            with (
                self.subTest(params=params),
                self.assertRaises(CodexBodyError) as caught,
            ):
                self.recover(**params)
            self.assertEqual(caught.exception.code, "codex_turn_recovery_ambiguous")
            self.assertFalse(caught.exception.retryable)
            self.assertEqual(self.fixture.journal.path.read_bytes(), before)

    def test_nonterminal_foreign_and_mismatched_input_remain_unknown(self) -> None:
        self.pending()
        before = self.fixture.journal.path.read_bytes()
        different = self.turn()
        different["items"][0]["content"][0]["text"] = "Another input"
        for params in (
            {"turn": self.turn(status="inProgress")},
            {"turn": self.turn(id="foreign")},
            {"turn": different},
            {"turn": self.turn(items=[])},
            {"thread_changes": {"sessionId": "foreign"}},
            {"thread_changes": {"cwd": "/unselected"}},
            {
                "notification": {
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": "foreign",
                        "turnId": "turn-a",
                        "itemId": "answer-a",
                        "delta": "unselected text",
                    },
                }
            },
        ):
            with (
                self.subTest(params=params),
                self.assertRaises(CodexBodyError) as caught,
            ):
                self.recover(**params)
            self.assertFalse(caught.exception.retryable)
            self.assertEqual(self.fixture.journal.path.read_bytes(), before)
        self.assertFalse((self.fixture.plan.profile_root / "turn-results").exists())

    def test_torn_original_result_is_preserved_with_separate_recovered_result(
        self,
    ) -> None:
        self.pending()
        directory = self.fixture.plan.profile_root / "turn-results"
        directory.mkdir(mode=0o700)
        path = directory / (self.fixture.request_id + ".json")
        path.write_bytes(b'{"incomplete":')
        path.chmod(0o600)
        self.recover()
        self.assertEqual(path.read_bytes(), b'{"incomplete":')
        recovered = directory / (self.fixture.request_id + ".recovered.json")
        self.assertEqual(recovered.stat().st_mode & 0o777, 0o600)

    def test_after_result_commit_retry_reuses_immutable_proof(self) -> None:
        self.pending()
        adapter = self.controller.adapter(self.script())
        with (
            mock.patch.object(adapter, "_record_handle", side_effect=OSError),
            self.assertRaises(CodexBodyError),
        ):
            adapter.recover_turn(request_id=self.fixture.request_id)
        path = (
            self.fixture.plan.profile_root
            / "turn-results"
            / (self.fixture.request_id + ".recovered.json")
        )
        before = path.read_bytes()
        result = self.recover(turn=self.turn(startedAt=123))
        self.assertEqual(result["handle"]["state"], "active")
        self.assertEqual(path.read_bytes(), before)

    def test_conflicting_retained_proof_never_clears_pending(self) -> None:
        self.pending()
        adapter = self.controller.adapter(self.script())
        with (
            mock.patch.object(adapter, "_record_handle", side_effect=OSError),
            self.assertRaises(CodexBodyError),
        ):
            adapter.recover_turn(request_id=self.fixture.request_id)
        before = self.fixture.journal.path.read_bytes()
        changed = self.turn()
        changed["items"][1]["text"] = "Different retained result"
        with self.assertRaises(CodexBodyError) as caught:
            self.recover(turn=changed)
        self.assertEqual(caught.exception.code, "codex_turn_recovery_result_drift")
        self.assertEqual(self.fixture.journal.path.read_bytes(), before)


class TurnCliTests(unittest.TestCase):
    """Real CLI, resume RPC, pipes and journals; admission/vendor seams synthetic."""

    def setUp(self) -> None:
        self.controller = TurnControllerTests(methodName="runTest")
        self.controller.setUp()
        self.addCleanup(self.controller.doCleanups)
        fixture = self.controller.fixture
        self.root = fixture.plan.profile_root.parent
        self.capability_fd = self.descriptor("key", bytes(32))
        self.input_fd = self.descriptor("input", b"PRIVATE_SYNTHETIC_PROMPT")
        self.provider_fd = self.descriptor("provider", b"PRIVATE_SYNTHETIC_PROVIDER")
        old = fixture.plan
        arguments = (*old.mcp_args[:5], str(self.capability_fd), *old.mcp_args[6:])
        fixture.plan = replace(old, profile_root=self.root / "cli", mcp_args=arguments)
        body.create_profile(
            fixture.plan, bootstrap_verifier=lambda *_: True, clock=lambda: fixture.now
        )
        core = {
            name: fixture.active[name]
            for name in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "matrix_session_id",
                "matrix_high_water",
                "thread_id",
                "session_tree_id",
                "turn_id",
                "state",
                "observed_at_ms",
            )
        }
        fixture.journal = body.RuntimeHandleJournal(
            fixture.plan.profile_root / "runtime-handles.jsonl", plan=fixture.plan
        )
        fixture.active = fixture.journal.append(core)
        fixture.active = fixture.journal.append({**core, "turn_id": "turn-before"})
        self.bundle = self.root / "bundle.json"
        self.bundle.write_text('{"synthetic":true}')
        self.bundle.chmod(0o600)
        self.document = self.root / "plan.json"
        self.document.write_text(json.dumps(fixture.plan.value))
        self.document.chmod(0o600)

    def descriptor(self, name: str, content: bytes) -> int:
        path = self.root / name
        path.write_bytes(content)
        path.chmod(0o600)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def script(self, *, status: str = "completed") -> str:
        plan = self.controller.fixture.plan
        source = profile_fixture.SuccessorProfileTests(methodName="runTest")
        source.workspace = plan.workspace
        source.plan = plan
        response = source.thread_response()
        response["thread"].update(id="thread-fixture", sessionId="session-fixture")
        server = {
            "name": "matrix",
            "authStatus": "unsupported",
            "runtimeStatus": "connected",
            "pluginId": None,
            "toolsError": None,
            "serverInfo": {"name": "daimon-matrix", "version": "0.1.0rc1"},
            "resourceTemplates": [],
            "resources": [
                {"uri": uri, "mimeType": "application/vnd.daimon-matrix+json"}
                for uri in (
                    "daimon:contract/server",
                    "daimon:contract/tools",
                    "daimon:contract/local-api",
                    "daimon:runtime/status",
                    "daimon:scope/me",
                    "daimon:scope/we",
                    "daimon:we/heads",
                    "daimon:we/projection",
                )
            ],
            "tools": {name: {"name": name} for name in body.MATRIX_TOOLS},
        }
        prefix = "import json,sys\n"
        for method, result in (
            ("thread/resume", response),
            ("mcpServerStatus/list", {"data": [server]}),
        ):
            prefix += (
                "request=json.loads(sys.stdin.readline())\n"
                f"assert request['method']=={method!r}\n"
                f"print(json.dumps({{'id':request['id'],'result':{result!r}}}),flush=True)\n"
            )
        return prefix + self.controller.script(
            status=status, answer="PRIVATE_SYNTHETIC_MODEL_ANSWER"
        )

    def invoke(
        self,
        *,
        status: str = "completed",
        alias: bool = False,
        recovery_script: str | None = None,
    ) -> tuple[int, bytes, str]:
        fixture = self.controller.fixture
        plan = fixture.plan
        adapter = self.controller.adapter(
            recovery_script
            if recovery_script is not None
            else self.script(status=status)
        )
        assert isinstance(adapter.transport, AppServerProcess)
        session = bridge.OwnerNativeSession(adapter, adapter.transport)
        bootstrap = plan.value["bootstrap"]
        current = SimpleNamespace(
            **{
                key: bootstrap[key]
                for key in (
                    "being_ref",
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                )
            },
            manifest_hash="a" * 64,
            capability_expires_at_ms=fixture.now + 60_000,
        )
        recovering = recovery_script is not None
        args = [
            "native-turn",
            "--action",
            "recover-turn" if recovering else "resume-turn",
        ]
        options: dict[str, Any] = {
            "bundle": self.bundle,
            "document": self.document,
            "profile-root": plan.profile_root,
            "workspace": plan.workspace,
            "binary": plan.codex_binary,
            "mcp-binary": plan.mcp_binary,
            "socket": plan.mcp_args[1],
            "client-config": plan.mcp_args[3],
            "request-dir": plan.mcp_args[7],
            "proof-journal": self.root / "proofs",
            "max-age-ms": 1000,
            "capability-key-fd": self.capability_fd,
            "provider-token-fd": self.provider_fd,
            "request-id": fixture.request_id,
        }
        if not recovering:
            options.update(
                {
                    "input-fd": self.provider_fd if alias else self.input_fd,
                    "timeout-seconds": 1,
                    "max-response-bytes": 4096,
                    "retain-until-ms": fixture.now + 60_000,
                }
            )
        for name, value in options.items():
            args.extend(("--" + name, str(value)))
        output = io.BytesIO()
        errors = io.StringIO()
        with (
            mock.patch.object(sys, "stdout", SimpleNamespace(buffer=output)),
            mock.patch.object(sys, "stderr", errors),
            mock.patch.object(time, "time_ns", return_value=fixture.now * 1_000_000),
            mock.patch("daimon_matrix.client.ClientConfig.load"),
            mock.patch.object(
                bridge, "owner_local_admission", return_value=(None, {}, current)
            ) as admission,
            mock.patch.object(bridge, "owner_cluster_body_reader"),
            mock.patch.object(
                bridge, "open_owner_native_session", return_value=session
            ) as opened,
        ):
            result = body.main(args)
            if alias:
                admission.assert_not_called()
                opened.assert_not_called()
            elif result != 2:
                self.assertEqual(
                    opened.call_args.kwargs["provider_token"],
                    "PRIVATE_SYNTHETIC_PROVIDER",
                )
        return result, output.getvalue(), errors.getvalue()

    def test_cli_resumes_once_retains_result_and_prints_only_metadata(self) -> None:
        code, output, errors = self.invoke()
        self.assertEqual((code, errors), (0, ""))
        receipt = json.loads(output)
        self.assertEqual(receipt["turn_status"], "completed")
        for private in (
            b"PRIVATE_SYNTHETIC_PROMPT",
            b"PRIVATE_SYNTHETIC_PROVIDER",
            b"PRIVATE_SYNTHETIC_MODEL_ANSWER",
        ):
            self.assertNotIn(private, output)
        fixture = self.controller.fixture
        saved = body.read_native_turn_result(fixture.plan, fixture.request_id)
        self.assertEqual(saved["result_id"], receipt["result_id"])
        intent = body.read_turn_intent(fixture.plan, fixture.request_id)
        anchor = next(
            handle
            for handle in fixture.journal.load()
            if handle["handle_id"] == intent["active_handle_id"]
        )
        self.assertEqual(anchor["turn_id"], "turn-before")
        self.assertEqual(
            saved["native_turn"]["items"][0]["text"], "PRIVATE_SYNTHETIC_MODEL_ANSWER"
        )
        before = fixture.journal.path.read_bytes()
        repeat, _, repeat_errors = self.invoke()
        self.assertEqual(repeat, 2)
        self.assertEqual(repeat_errors.strip(), "turn_request_already_reserved")
        self.assertEqual(fixture.journal.path.read_bytes(), before)

    def test_cli_failed_turn_retains_private_result_and_returns_failure(self) -> None:
        code, output, errors = self.invoke(status="failed")
        self.assertEqual((code, errors), (1, ""))
        self.assertEqual(json.loads(output)["turn_status"], "failed")
        self.assertNotIn(b"PRIVATE_PROVIDER_TOKEN", output)

    def test_cli_refuses_credential_input_alias_before_admission(self) -> None:
        code, output, errors = self.invoke(alias=True)
        self.assertEqual((code, output), (2, b""))
        self.assertEqual(errors.strip(), "codex_turn_descriptor_alias")
        self.assertFalse((self.controller.io.root / "accepted").exists())

    def test_cli_recovers_selected_intent_without_prompt_or_resume(self) -> None:
        recovery = TurnRecoveryTests(methodName="runTest")
        recovery.controller = self.controller
        recovery.fixture = self.controller.fixture
        recovery.pending(known=False, baseline="turn-before")
        code, output, errors = self.invoke(
            recovery_script=recovery.script(
                cursor="synthetic-cursor", preceding="turn-before"
            )
        )
        self.assertEqual((code, errors), (0, ""))
        receipt = json.loads(output)
        self.assertEqual(receipt["action"], "recover-turn")
        self.assertEqual(receipt["model_inputs"], 0)
        self.assertNotIn(b"Private answer", output)
        self.assertNotIn(b"Private synthetic input", output)
        self.assertNotIn(b"PRIVATE_SYNTHETIC_PROVIDER", output)
        self.assertEqual(receipt["handle"]["state"], "active")

    def test_cli_recovery_refuses_input_before_provider_or_admission(self) -> None:
        with (
            mock.patch.object(body, "read_native_provider_token") as token,
            mock.patch.object(bridge, "owner_local_admission") as admission,
            mock.patch.object(sys, "stderr", io.StringIO()),
        ):
            code = body.main(
                [
                    "native-turn",
                    "--action",
                    "recover-turn",
                    "--input-fd",
                    "99",
                    "--provider-token-fd",
                    "98",
                    "--capability-key-fd",
                    "97",
                    "--request-id",
                    self.controller.fixture.request_id,
                    *[
                        value
                        for name in (
                            "bundle",
                            "client-config",
                            "socket",
                            "document",
                            "profile-root",
                            "workspace",
                            "binary",
                            "mcp-binary",
                            "request-dir",
                        )
                        for value in ("--" + name, str(self.root / name))
                    ],
                ]
            )
            self.assertEqual(code, 2)
            token.assert_not_called()
            admission.assert_not_called()


if __name__ == "__main__":
    unittest.main()
