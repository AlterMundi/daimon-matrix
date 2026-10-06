"""Rendered owner client over real private files, Unix RPC and sealed intake."""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import threading
import uuid
from types import SimpleNamespace
from typing import Any, cast

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
from daimon_matrix.daemon import acquire_lock, serve_connection
from daimon_matrix.local_api import create_capability
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

        def fault(stage: str) -> None:
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

    def write_config(self, directory: Any, capability: Any, key_name: str) -> None:
        (directory / key_name).write_bytes(capability.key)
        (directory / key_name).chmod(0o600)
        (directory / "client.json").write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": capability.descriptor,
                    "expected_server": self.origins["legion"],
                    "runtime_id": "dm:runtime:v1:" + "a" * 43,
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
