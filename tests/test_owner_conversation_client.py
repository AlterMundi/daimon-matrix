"""Rendered owner client over real private files, Unix RPC and sealed intake."""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import threading
import time
import uuid
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
from daimon_matrix.communication import MESSAGE_PAYLOAD_SCHEMA
from daimon_matrix.daemon import acquire_lock, serve_connection
from daimon_matrix.local_api import create_capability
from daimon_matrix.native_egress import NativeEgressError
from daimon_matrix.neutral_binding import (
    owner_client_plan_from_mapping,
    render_owner_client,
)
from daimon_matrix.peer_transport import PeerTransportAmbiguous, PeerTransportError
from daimon_matrix.scopes import ScopeResolver
from daimon_matrix.service import OPERATOR_CAPABILITY_PROFILES, HostedWeave
from daimon_matrix.we_messaging import WeConversation
from tests.test_dm022_ledger import NOW, seed
from tests.test_dm051_sealed import SealedFixture
from tests.test_neutral_binding import client_plan_value


class OwnerConversationClientTests(SealedFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_dir = self.root_path / "owner"
        self.runtime_dir = self.state_dir / "runtime"
        self.runtime_dir.mkdir(mode=0o700, parents=True)
        self.state_dir.chmod(0o700)
        self.primary = create_capability(
            seed("owner-observe"),
            client_id="client:owner-observe",
            methods=sorted(OPERATOR_CAPABILITY_PROFILES["observe"]),
            not_before_ms=NOW - 1000,
            not_after_ms=NOW + 100_000,
        )
        self.weave = create_capability(
            seed("owner-weave"),
            client_id="client:owner-weave",
            methods=sorted(OPERATOR_CAPABILITY_PROFILES["weave"]),
            not_before_ms=NOW - 1000,
            not_after_ms=NOW + 100_000,
        )
        self.write_config(self.runtime_dir, self.primary, "client.key")
        self.profile_dir = self.runtime_dir / "operator-clients" / "weave"
        self.profile_dir.mkdir(mode=0o700, parents=True)
        self.write_config(self.profile_dir, self.weave, "capability.key")
        self.delivery_attempts = 0
        receiver = WeConversation(
            self.ledger_b,
            signer=self.signers["daimonmatrix"],
            custody=self.custodies["daimonmatrix"],
            clock=lambda: NOW + 5,
        )

        def deliver(payload: Any, **_kwargs: Any) -> Any:
            self.assertTrue(list((self.state_dir / "owner-requests").glob("*.json")))
            self.delivery_attempts += 1
            return receiver.intake(payload)

        sender = WeConversation(
            self.ledger_a,
            signer=self.signers["legion"],
            custody=self.custodies["legion"],
            clock=lambda: NOW,
        )
        self.service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {cap.capability_id: cap for cap in (self.primary, self.weave)},
            lambda: NOW,
            "dm:runtime:v1:" + "a" * 43,
            "owner-test",
            scopes=ScopeResolver(self.ledger_a, clock=lambda: NOW),
            peer_context=cast(
                Any,
                SimpleNamespace(
                    configured=lambda _embodiment: (
                        None,
                        SimpleNamespace(call=deliver),
                    ),
                    authority=self.authority,
                    local_origin=self.origins["legion"],
                ),
            ),
            we_lane=sender,
        )
        self.owner: dict[str, Any] = {"__name__": "owner_test"}
        script = render_owner_client(
            owner_client_plan_from_mapping(client_plan_value())
        )
        exec(compile(script, "rendered-owner-client", "exec"), self.owner)
        self.owner.update(
            STATE=self.state_dir, RUNTIME=self.runtime_dir, _clock=lambda: NOW
        )
        self.socket_path = self.runtime_dir / "matrix.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.stop = threading.Event()
        self.drop_reply = False
        self.before_reply: Any = None

        def fault(stage: str) -> None:
            if self.before_reply is not None and stage == "after_dispatch_before_write":
                self.before_reply()
            if self.drop_reply and stage == "after_dispatch_before_write":
                self.drop_reply = False
                raise ConnectionError("synthetic lost reply")

        def serve() -> None:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    serve_connection(
                        cast(Any, SimpleNamespace(service=self.service)),
                        connection,
                        fault_hook=fault,
                    )

        self.thread = threading.Thread(target=serve)
        self.thread.start()

    def write_config(
        self,
        directory: Any,
        capability: Any,
        key_name: str,
        *,
        runtime_id: str = "dm:runtime:v1:" + "a" * 43,
    ) -> None:
        (directory / key_name).write_bytes(capability.key)
        (directory / key_name).chmod(0o600)
        (directory / "client.json").write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": capability.descriptor,
                    "expected_server": self.origins["legion"],
                    "runtime_id": runtime_id,
                    "runtime_label": "owner-test",
                }
            )
        )
        (directory / "client.json").chmod(0o600)

    def tearDown(self) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        self.listener.close()
        super().tearDown()

    def run_client(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        if args[0] == "say" and "--retry" not in args:
            args = (*args, "--ttl-ms", "30000")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.owner["main"](list(args))
        return code, out.getvalue(), err.getvalue()

    def test_real_unix_client_preserves_typed_uncertain_delivery_and_cached_retry(
        self,
    ) -> None:
        assert self.service.peer_context is not None
        attempted: list[Any] = []

        def uncertain(payload: Any, **kwargs: Any) -> Any:
            attempted.append(payload)
            raise NativeEgressError("egress_echo_not_confirmed")

        self.service = replace(
            self.service,
            peer_context=cast(
                Any,
                SimpleNamespace(
                    configured=lambda _id: (None, SimpleNamespace(call=uncertain)),
                    authority=self.authority,
                    local_origin=self.origins["legion"],
                ),
            ),
        )
        request_id = str(uuid.uuid4())
        first = self.run_client(
            "say",
            "--to",
            "embodiment:daimonmatrix",
            "--text",
            "human request",
            "--request-id",
            request_id,
        )
        self.assertEqual(first[0], 3, first[2])
        result = json.loads(first[1])["result"]
        self.assertEqual(result["deliveries"][0]["state"], "undetermined")
        self.assertEqual(result["deliveries"][0]["error"], "egress_echo_not_confirmed")
        self.assertIsNotNone(self.ledger_a.event(result["message_id"]))
        self.assertNotIn("receipt_event_id", result["deliveries"][0])
        self.assertEqual(self.run_client("say", "--retry", request_id)[:2], first[:2])
        self.assertEqual(len(attempted), 1)

    def test_saved_expired_seal_is_typed_and_never_resealed_through_unix(self) -> None:
        request_id = str(uuid.uuid4())
        first = self.run_client(
            "say",
            "--to",
            "embodiment:daimonmatrix",
            "--text",
            "expires",
            "--request-id",
            request_id,
        )
        self.assertEqual(first[0], 0, first[2])
        params = json.loads(
            (self.state_dir / "owner-requests" / f"{request_id}.json").read_bytes()
        )["params"]
        self.owner["_clock"] = lambda: NOW + 31_000
        self.service = replace(
            self.service,
            clock=lambda: NOW + 31_000,
            we_lane=WeConversation(
                self.ledger_a,
                signer=self.signers["legion"],
                custody=self.custodies["legion"],
                clock=lambda: NOW + 31_000,
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "sealed_delivery_rejected"):
            self.owner["_call"]("we.converse", params)
        self.assertEqual(self.delivery_attempts, 1)
        self.assertEqual(self.run_client("say", "--retry", request_id)[:2], first[:2])

    def peer_message(self, thread: str, text: str, *, occurred: int = NOW) -> str:
        event = self.ledger_b.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {"scope": "/we", "operation": "read", "thread_id": thread},
                "body": {"addressee": ["embodiment:legion"], "text": text},
            },
            signer=self.signers["daimonmatrix"],
            occurred_at_ms=occurred,
        )
        self.ledger_a.ingest([event], source="peer")
        return cast(str, event["event_id"])

    def start_watch(self, thread: str, *extra: str) -> tuple[str, dict[str, Any]]:
        watch_id = str(uuid.uuid4())
        code, output, error = self.run_client(
            "watch",
            "--watch-id",
            watch_id,
            "--peer",
            "embodiment:daimonmatrix",
            "--thread",
            thread,
            "--task",
            "human-directed skills update",
            "--wait",
            "0",
            *extra,
        )
        self.assertEqual(code, 0, error)
        return watch_id, json.loads(output)

    def test_watch_scans_filtered_backlog_and_acknowledges_equal_time_pages(
        self,
    ) -> None:
        selected = str(uuid.uuid4())
        ignored = str(uuid.uuid4())
        for i in range(5):
            self.peer_message(ignored, f"other thread {i}")
            self.append(self.ledger_a, "legion", "unrelated")
        expected = [self.peer_message(selected, f"selected {i}") for i in range(5)]
        watch_id, result = self.start_watch(selected, "--limit", "2")
        received: list[str] = []
        for _ in range(25):
            if result["status"] == "page":
                received.extend(row["event_id"] for row in result["page"]["entries"])
                ack_args = (
                    "watch",
                    "--watch-id",
                    watch_id,
                    "--ack",
                    result["page"]["page_id"],
                )
                first = self.run_client(*ack_args)
                self.assertEqual(first[0], 0, first[2])
                self.assertEqual(json.loads(first[1])["status"], "acknowledged")
                self.assertEqual(self.run_client(*ack_args)[:2], first[:2])
            code, output, error = self.run_client(
                "watch", "--watch-id", watch_id, "--wait", "0", "--limit", "2"
            )
            self.assertEqual(code, 0, error)
            result = json.loads(output)
            if len(received) == len(expected) and result["status"] == "waiting":
                break
        self.assertEqual(received, expected)
        late = self.peer_message(selected, "late older authoring", occurred=NOW - 5)
        code, output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0"
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(
            [row["event_id"] for row in json.loads(output)["page"]["entries"]], [late]
        )
        self.assertEqual(self.delivery_attempts, 0)

    def test_watch_persists_page_before_lost_output_and_refuses_restored_boundary(
        self,
    ) -> None:
        selected = str(uuid.uuid4())
        self.ledger_a.initialize()
        original = self.ledger_a.path.read_bytes()
        event_id = self.peer_message(selected, "must survive lost stdout")
        watch_id = str(uuid.uuid4())
        with patch.dict(
            self.owner,
            {"_watch_output": lambda *_: (_ for _ in ()).throw(BrokenPipeError())},
        ):
            self.assertEqual(
                self.run_client(
                    "watch",
                    "--watch-id",
                    watch_id,
                    "--peer",
                    "embodiment:daimonmatrix",
                    "--thread",
                    selected,
                    "--task",
                    "skills",
                    "--wait",
                    "0",
                )[0],
                2,
            )
        path = self.state_dir / "owner-watches" / (watch_id + ".json")
        saved = json.loads(path.read_bytes())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        args = ("watch", "--watch-id", watch_id, "--wait", "0")
        first = self.run_client(*args)
        self.assertEqual(first[0], 0, first[2])
        self.assertEqual(json.loads(first[1])["page"], saved["pending"])
        self.assertEqual(
            json.loads(first[1])["page"]["entries"][0]["event_id"], event_id
        )
        self.assertEqual(self.run_client(*args)[:2], first[:2])
        self.ledger_a.path.write_bytes(original)
        code, output, error = self.run_client(*args)
        self.assertEqual((code, output), (2, ""))
        self.assertIn("invalid_known_cursor", error)
        self.assertEqual(json.loads(path.read_bytes())["pending"], saved["pending"])

    def test_watch_scope_revocation_and_private_state(self) -> None:
        selected = str(uuid.uuid4())
        watch_id, _ = self.start_watch(selected)
        args = ("watch", "--watch-id", watch_id, "--wait", "0")
        for change in (
            ("--task", "other"),
            ("--peer", "embodiment:legion"),
            ("--thread", str(uuid.uuid4())),
            ("--from-now",),
            ("--ack", str(uuid.uuid4())),
        ):
            self.assertEqual(self.run_client(*args, *change)[0], 2)
        self.assertEqual(self.run_client(*args, "--stop")[0], 0)
        self.assertIn("watch_revoked", self.run_client(*args)[2])
        path = self.state_dir / "owner-watches" / (watch_id + ".json")
        self.assertFalse(json.loads(path.read_bytes())["active"])
        (self.state_dir / "owner-watches").chmod(0o755)
        self.assertIn("watch_parent_not_owner_only", self.run_client(*args)[2])

    def test_watch_fifo_is_rejected_without_waiting_for_a_writer(self) -> None:
        watch_id, _ = self.start_watch(str(uuid.uuid4()))
        path = self.state_dir / "owner-watches" / (watch_id + ".json")
        path.unlink()
        os.mkfifo(path, 0o600)
        start = time.monotonic()
        code, output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0.05"
        )
        self.assertEqual((code, output), (2, ""))
        self.assertIn("watch_state_not_owner_only", error)
        self.assertLess(time.monotonic() - start, 0.2)

    def test_from_now_retains_anchor_when_initial_output_is_lost(self) -> None:
        selected = str(uuid.uuid4())
        self.peer_message(selected, "previous message")
        watch_id = str(uuid.uuid4())
        with patch.dict(
            self.owner,
            {"_watch_output": lambda *_: (_ for _ in ()).throw(BrokenPipeError())},
        ):
            self.assertEqual(
                self.run_client(
                    "watch",
                    "--watch-id",
                    watch_id,
                    "--peer",
                    "embodiment:daimonmatrix",
                    "--thread",
                    selected,
                    "--task",
                    "skills",
                    "--from-now",
                    "--wait",
                    "0",
                )[0],
                2,
            )
        late = self.peer_message(
            selected, "arrived after failed output", occurred=NOW - 5
        )
        code, output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0"
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(
            [row["event_id"] for row in json.loads(output)["page"]["entries"]], [late]
        )

    def test_wait_is_finite_and_stop_can_revoke_concurrent_reader(self) -> None:
        selected = str(uuid.uuid4())
        watch_id, _ = self.start_watch(selected)
        args = SimpleNamespace(
            watch_id=watch_id,
            peer=None,
            thread=None,
            task=None,
            from_now=False,
            wait=2.0,
            limit=64,
            ack=None,
            stop=False,
        )
        reached = threading.Event()
        release = threading.Event()

        def before_reply() -> None:
            reached.set()
            release.wait(0.5)

        self.before_reply = before_reply
        results: list[str] = []
        errors: list[BaseException] = []

        def waiting() -> None:
            try:
                self.owner["_watch"](args)
            except BaseException as error:
                errors.append(error)

        def capture_output(_value: Any, status: str) -> int:
            results.append(status)
            return 0

        with patch.dict(self.owner, {"_watch_output": capture_output}):
            reader = threading.Thread(target=waiting)
            reader.start()
            self.assertTrue(reached.wait(1))
            self.assertEqual(
                self.run_client("watch", "--watch-id", watch_id, "--stop")[0], 0
            )
            release.set()
            reader.join(timeout=1)
            self.assertFalse(reader.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, ["stopped", "stopped"])

        # A successful real authenticated RPC gets a normal scheduling window.
        # Preserve the separate80ms/300ms intentional deadline refusal below.
        def delayed_first_reply() -> None:
            self.before_reply = None
            time.sleep(0.2)

        other, _ = self.start_watch(selected)
        self.before_reply = delayed_first_reply
        deadline: list[float] = []
        original_call = self.owner["_call"]

        def monotonic() -> float:
            now = time.monotonic()
            if not deadline:
                deadline.append(now + 1.0)
            return now

        def call_before_deadline(*args: Any, **kwargs: Any) -> Any:
            self.assertLess(time.monotonic(), deadline[0], "RPC began after wait ended")
            return original_call(*args, **kwargs)

        start = time.monotonic()
        with patch.dict(
            self.owner,
            {
                "time": SimpleNamespace(monotonic=monotonic, sleep=time.sleep),
                "_call": call_before_deadline,
            },
        ):
            code, output, error = self.run_client(
                "watch", "--watch-id", other, "--wait", "1.0"
            )
        elapsed = time.monotonic() - start
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "waiting")
        self.assertLess(elapsed, 1.6)

    def test_ack_during_authenticated_read_does_not_restart_an_elapsed_wait(
        self,
    ) -> None:
        selected = str(uuid.uuid4())
        self.peer_message(selected, "pending page")
        watch_id, initial = self.start_watch(selected)
        original_call = self.owner["_call"]
        calls: list[str] = []

        def acknowledge_after_reply(method: str, *args: Any, **kwargs: Any) -> Any:
            calls.append(method)
            self.assertEqual(
                len(calls), 1, "RPC repeated after acknowledgement and deadline"
            )
            page = original_call(method, *args, **kwargs)
            code, _output, error = self.run_client(
                "watch",
                "--watch-id",
                watch_id,
                "--ack",
                initial["page"]["page_id"],
            )
            self.assertEqual(code, 0, error)
            # Simulate descheduling after an authenticated reply and a real local ack.
            time.sleep(1.1)
            return page

        with patch.dict(self.owner, {"_call": acknowledge_after_reply}):
            code, output, error = self.run_client(
                "watch", "--watch-id", watch_id, "--wait", "1.0"
            )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "waiting")
        self.assertIsNone(json.loads(output)["page"])
        self.assertEqual(calls, ["we.conversation.page"])

    def test_wait_transport_deadline_and_daemon_only_path(self) -> None:
        selected = str(uuid.uuid4())
        watch_id, _ = self.start_watch(selected)
        self.before_reply = lambda: time.sleep(0.3)
        start = time.monotonic()
        code, _output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0.08"
        )
        self.assertEqual(code, 2)
        self.assertIn("watch_daemon_unavailable", error)

        self.assertLess(time.monotonic() - start, 0.25)
        self.before_reply = None
        self.stop.set()
        self.thread.join(timeout=3)
        self.listener.close()
        code, _output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0"
        )
        self.assertEqual(code, 2)
        self.assertIn("watch_daemon_unavailable", error)

    def test_active_wait_cannot_switch_its_authenticated_runtime(self) -> None:
        selected = str(uuid.uuid4())
        watch_id, _ = self.start_watch(selected)
        changed = False

        def change_runtime() -> None:
            nonlocal changed
            if changed:
                return
            changed = True
            new_id = "dm:runtime:v1:" + "b" * 43
            self.write_config(
                self.runtime_dir, self.primary, "client.key", runtime_id=new_id
            )
            self.write_config(
                self.profile_dir, self.weave, "capability.key", runtime_id=new_id
            )
            self.service = replace(self.service, runtime_id=new_id)
            self.peer_message(selected, "new runtime must not enter old watch")

        self.before_reply = change_runtime
        code, output, error = self.run_client(
            "watch", "--watch-id", watch_id, "--wait", "0.8"
        )
        self.assertEqual((code, output), (2, ""))
        self.assertIn("daemon_response_rejected", error)
        path = self.state_dir / "owner-watches" / (watch_id + ".json")
        state = json.loads(path.read_bytes())
        self.assertEqual(state["runtime_id"], "dm:runtime:v1:" + "a" * 43)
        self.assertIsNone(state["pending"])
        self.assertEqual(self.delivery_attempts, 0)

    def test_say_routes_issued_profile_and_proves_receiving_intake(self) -> None:
        primary_bytes = (self.runtime_dir / "client.json").read_bytes()
        request_id = str(uuid.uuid4())
        code, output, _err = self.run_client(
            "say",
            "--text",
            "portable skills",
            "--to",
            "embodiment:daimonmatrix",
            "--request-id",
            request_id,
        )
        self.assertEqual(code, 0, output)
        result = json.loads(output)["result"]
        self.assertEqual(result["deliveries"][0]["state"], "delivered")
        receipt_id = result["deliveries"][0]["receipt_event_id"]
        self.assertIsNotNone(self.ledger_b.event(receipt_id))
        message = self.ledger_b.event(result["message_id"])
        assert message is not None
        self.assertEqual(
            message["payload"]["body"]["text"],
            "portable skills",
        )
        path = self.state_dir / "owner-requests" / (request_id + ".json")
        saved_bytes = path.read_bytes()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_client("say", "--retry", request_id)[0], 0)
        self.assertEqual(self.delivery_attempts, 1)
        self.assertEqual(path.read_bytes(), saved_bytes)
        self.assertEqual((self.runtime_dir / "client.json").read_bytes(), primary_bytes)
        self.assertEqual(self.run_client("read")[0], 0)

    def test_lost_response_reuses_persisted_operation_without_duplicate_message(
        self,
    ) -> None:
        request_id = str(uuid.uuid4())
        self.drop_reply = True
        code, _output, err = self.run_client(
            "say",
            "--text",
            "one message",
            "--to",
            "embodiment:daimonmatrix",
            "--request-id",
            request_id,
        )
        self.assertEqual(code, 2)
        self.assertIn(request_id, err)
        self.assertEqual(self.delivery_attempts, 1)
        code, output, _err = self.run_client("say", "--retry", request_id)
        self.assertEqual(code, 0)
        message_id = json.loads(output)["result"]["message_id"]
        self.assertIsNotNone(self.ledger_b.event(message_id))
        self.assertEqual(self.delivery_attempts, 1)

    def test_misbound_or_missing_profile_refuses_before_any_effect(self) -> None:
        path = self.profile_dir / "client.json"
        config = json.loads(path.read_bytes())
        config["expected_server"] = self.origins["daimonmatrix"]
        path.write_bytes(canonical_bytes(config))
        code, output, err = self.run_client("say", "--text", "refuse")
        self.assertEqual((code, output), (2, ""))
        self.assertIn("operator_profile_body_mismatch", err)
        path.unlink()
        self.assertEqual(self.run_client("say", "--text", "missing")[0], 2)
        self.assertEqual(self.delivery_attempts, 0)
        self.assertFalse((self.state_dir / "owner-requests").exists())

    def test_runtime_lock_prevents_fallback_after_daemon_becomes_unreachable(
        self,
    ) -> None:
        self.stop.set()
        self.thread.join(timeout=3)
        self.listener.close()
        descriptor = acquire_lock(self.runtime_dir)
        try:
            # There is deliberately no password/runtime bundle. Attempting an
            # in-process load would fail differently and violate the lock.
            code, _output, err = self.run_client("status")
            self.assertEqual(code, 2)
            self.assertIn("daemon_unavailable_runtime_locked", err)
        finally:
            os.close(descriptor)

    def test_methods_reports_actual_disjoint_profiles(self) -> None:
        code, output, _err = self.run_client("methods")
        self.assertEqual(code, 0)
        methods = json.loads(output)
        self.assertNotIn("we.converse", methods["primary"]["methods"])
        self.assertIn("we.converse", methods["weave"]["methods"])
        self.assertNotIn("relationships", methods)

    def test_native_uncertain_and_rejected_outcomes_are_not_success(self) -> None:
        for error, state in (
            (PeerTransportAmbiguous, "undetermined"),
            (PeerTransportError, "rejected"),
        ):

            def refuse(
                _embodiment: str, error: type[PeerTransportError] = error
            ) -> Any:
                raise error()

            cast(Any, self.service.peer_context).configured = refuse
            code, output, _err = self.run_client(
                "say", "--text", state, "--to", "embodiment:daimonmatrix"
            )
            self.assertEqual(code, 3)
            operation = json.loads(output)
            self.assertEqual(operation["result"]["deliveries"][0]["state"], state)
            again = self.run_client("say", "--retry", operation["request_id"])
            self.assertEqual(again[:2], (code, output))
        self.assertEqual(self.delivery_attempts, 0)

    def test_existing_id_and_unsafe_request_directory_refuse(self) -> None:
        request_id = str(uuid.uuid4())
        args = (
            "say",
            "--text",
            "once",
            "--to",
            "embodiment:daimonmatrix",
            "--request-id",
            request_id,
        )
        self.assertEqual(self.run_client(*args)[0], 0)
        code, _out, err = self.run_client(*args)
        self.assertEqual(code, 2)
        self.assertIn("request_file_exists", err)
        (self.state_dir / "owner-requests").chmod(0o755)
        code, _out, err = self.run_client("say", "--retry", request_id)
        self.assertEqual(code, 2)
        self.assertIn("request_store_parent_not_owner_only", err)
        self.assertEqual(self.delivery_attempts, 1)
