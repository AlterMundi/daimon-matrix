"""Independent foreign intake: synthetic keys, real signed grants and HPKE."""

from __future__ import annotations

import copy
import http.client
import http.server
import json
import os
import select
import tempfile
import threading
import unittest
from collections.abc import Callable
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from typing import Any, TypedDict, cast
from unittest.mock import Mock, patch

from daimon_matrix import daemon
from daimon_matrix import runtime as runtime_module
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.ledger import Ledger
from daimon_matrix.relationship_store import RelationshipStore
from daimon_matrix.runtime import load_runtime
from daimon_matrix.sealed import (
    DisclosureAuthorization,
    KeystoreDeliveryCustody,
    RecipientTarget,
    seal_event,
)
from daimon_matrix.synthetic_relationships import NOW, _identity, _seed, _uuid
from daimon_matrix.weave import create_event
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture

ROOT = Path(__file__).resolve().parents[1]
TEXT = "Only the independently authorized recipient may read this native message."


def custody(root: Path, label: str) -> KeystoreDeliveryCustody:
    identity = _identity(label)
    root.mkdir(mode=0o700)
    store = EncryptedKeystore.create(
        root / "keys.json",
        lambda: bytearray(b"synthetic-native-messaging"),
        control_head=identity.state.head,
        secrets={
            "sealed.signing.v1:test": _seed(f"{label}:signing"),
            "sealed.encryption.v1:test": _seed(f"{label}:encryption"),
        },
    )
    return KeystoreDeliveryCustody(
        store,
        lambda: bytearray(b"synthetic-native-messaging"),
        control_head=identity.state.head,
        counter=1,
        signing_slots={
            identity.credential["body"]["signing_key"][
                "key_id"
            ]: "sealed.signing.v1:test"
        },
        encryption_slots={
            identity.credential["body"]["encryption_key"][
                "key_id"
            ]: "sealed.encryption.v1:test"
        },
    )


class Pair:
    def __init__(self, root: Path) -> None:
        from daimon_matrix.messaging import (
            GrantReference,
            MessagingChannel,
            MessagingPeerPolicy,
        )
        from daimon_matrix.messaging_store import MessagingInboxStore

        self.sender = _identity("founder")
        self.recipient = _identity("member")
        # Only public RootAuthority objects are injected into the receiver resolver.
        public = {
            identity.state.being_ref: copy.deepcopy(identity.authority)
            for identity in (self.sender, self.recipient, _identity("delegate"))
        }
        self.public = public
        self.sender_relationships = RelationshipStore(
            root / "sender" / "relationships.sqlite3",
            authority_resolver=lambda being_ref: public[being_ref],
        )
        self.receiver_relationships = RelationshipStore(
            root / "receiver" / "relationships.sqlite3",
            authority_resolver=lambda being_ref: public[being_ref],
        )
        self.history = [
            json.loads(path.read_bytes())
            for path in sorted((ROOT / "vectors/relationships/v1/valid").glob("*.json"))
        ]
        for event in self.history:
            if event["occurred_at_ms"] <= NOW + 7:
                self.sender_relationships.ingest(event)
                self.receiver_relationships.ingest(copy.deepcopy(event))
        self.grant = next(
            event
            for event in self.history
            if event["kind"] == "matrix/relationship-grant"
            and event["being_ref"] == self.sender.state.being_ref
        )
        membership = next(
            event
            for event in self.history
            if event["kind"] == "matrix/tribe-membership-acceptance"
            and event["being_ref"] == self.recipient.state.being_ref
        )
        self.policy = MessagingPeerPolicy(
            peer_being_ref=self.sender.state.being_ref,
            peer_embodiment_id=self.sender.origin["embodiment_id"],
            peer_credential_id=self.sender.credential["artifact_id"],
            relationship_id=self.grant["payload"]["relationship_id"],
            tribe_ref=self.grant["payload"]["tribe_ref"],
            membership_ref=membership["event_id"],
            resource_ref=self.grant["payload"]["permissions"][0]["resource_ref"],
            operation="read",
            classification="shareable",
            grant_refs=(
                GrantReference(
                    self.grant["payload"]["grant_id"],
                    self.grant["event_id"],
                    self.grant["content_hash"],
                ),
            ),
        )
        self.sender_custody = custody(root / "sender" / "custody", "founder")
        self.receiver_custody = custody(root / "receiver" / "custody", "member")
        self.now = NOW + 10
        self.store_path = root / "receiver" / "foreign-inbox.sqlite3"
        self.store = MessagingInboxStore(self.store_path)
        self.channel_options = dict(
            policy=self.policy,
            local_being_ref=self.recipient.state.being_ref,
            local_credential_id=self.recipient.credential["artifact_id"],
            authority_resolver=lambda being_ref: public[being_ref],
            custody=self.receiver_custody,
        )
        self.receiver = MessagingChannel(
            **self.channel_options,
            relationships=self.receiver_relationships,
            inbox=self.store,
            clock=lambda: self.now,
        )
        self.sender_context = MessagingChannel(
            **{**self.channel_options, "custody": self.sender_custody},
            relationships=self.sender_relationships,
            inbox=MessagingInboxStore(root / "sender" / "unused-inbox.sqlite3"),
            clock=lambda: NOW + 10,
        )
        self.local_ledger = Ledger(
            root / "receiver" / "local.sqlite3",
            authority=self.recipient.authority,
            local_origin=self.recipient.origin,
            clock=lambda: NOW + 10,
        )
        self.local_ledger.initialize()

    def event(
        self,
        subject: str,
        payload: dict[str, Any],
        sequence: int,
        parents: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        return create_event(
            self.sender.authority,
            self.sender.origin,
            self.sender.signer,
            event_id=_uuid(f"native:{subject}:{sequence}"),
            sequence=sequence,
            previous_event_id=_uuid(f"native:previous:{sequence}"),
            occurred_at_ms=NOW + 8,
            causal_parents=parents,
            kind="experience.observed",
            subject=subject,
            payload=payload,
            sensitivity="shareable",
        )

    def wire(
        self, sequence: int = 100, *, text: str = TEXT
    ) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any]]:
        message = self.event(
            "communication",
            {
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {"text": text, "resource_ref": self.policy.resource_ref},
                "intent": {
                    "operation": "read",
                    "scope": "/tribe",
                    "thread_id": _uuid("native-thread"),
                },
                "reply": None,
            },
            sequence,
        )
        resolution = self.event(
            "communication-resolution",
            {
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/tribe",
                "targets": [
                    {
                        "evidence_cursor": "signed-selection-not-grant-authority",
                        "receipt_origin_embodiment_id": self.recipient.origin[
                            "embodiment_id"
                        ],
                        "recipient_id": self.policy.membership_ref,
                        "recipient_type": "relationship",
                        "scope_kind": "relationship",
                    }
                ],
            },
            sequence + 1,
            (message["event_id"],),
        )
        target = RecipientTarget(
            self.recipient.authority, self.recipient.credential["artifact_id"]
        )
        authorization = DisclosureAuthorization.from_relationship_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=self.sender.authority,
            recipient_targets=[target],
            disclosures={self.policy.membership_ref: self.sender_context.disclosure()},
            expires_at_ms=NOW + 30_000,
            authorization_id=_uuid(f"native-auth:{sequence}"),
        )
        evidence = self.event(
            "communication-evidence",
            {
                "schema": "dm.communication.evidence-package/v1",
                "message_id": message["event_id"],
                "message_hash": message["content_hash"],
                "resolution_event": resolution,
                "message_authorization_id": authorization.value["authorization_id"],
                "message_authorized_at_ms": authorization.value["authorized_at_ms"],
                "message_expires_at_ms": authorization.value["expires_at_ms"],
            },
            sequence + 2,
        )
        bootstrap = self.sender_context.evidence_authorization(
            evidence,
            authorized_at_ms=NOW + 10,
            expires_at_ms=NOW + 20_000,
            authorization_id=_uuid(f"native-bootstrap:{sequence}"),
        )
        options: dict[str, Any] = dict(
            sender_authority=self.sender.authority,
            recipients=[target],
            custody=self.sender_custody,
            issued_at_ms=NOW + 10,
            expires_at_ms=NOW + 20_000,
        )
        return (
            seal_event(evidence, authorization=bootstrap, **options),
            seal_event(message, authorization=authorization, **options),
            message,
            evidence,
        )


class _SendRequest(TypedDict):
    client_id: str
    send_id: str
    thread_id: str
    text: str


class NativeMessagingDaemonLifecycleTests(RuntimeFixture):
    def test_listener_start_failure_closes_without_waiting_for_absent_thread(
        self,
    ) -> None:
        root, _, _ = self.make_bundle()
        runtime = load_runtime(
            root, "runtime.json", lambda: bytearray(PASSWORD), clock=lambda: NOW
        )
        ingress = Mock()
        runtime = replace(
            runtime,
            messaging_http=runtime_module.MessagingHTTPContext(
                listen=("127.0.0.1", 0),
                evidence_ingress=ingress,
                message_ingress=ingress,
            ),
        )
        server = Mock()
        with (
            patch.object(daemon, "create_messaging_http_server", return_value=server),
            patch.object(
                threading.Thread,
                "start",
                side_effect=OSError("synthetic-thread-start-failure"),
            ),
            self.assertRaisesRegex(OSError, "synthetic-thread-start-failure"),
        ):
            daemon.serve_forever(runtime)
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once_with()
        self.assertFalse(runtime.socket_path.exists())

    def test_shutdown_waits_for_inflight_messaging_intake(self) -> None:
        root, _, _ = self.make_bundle()
        runtime = load_runtime(
            root, "runtime.json", lambda: bytearray(PASSWORD), clock=lambda: NOW
        )
        entered, release, returned = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        ingress = Mock()

        def handle(raw: bytes) -> bytes:
            entered.set()
            release.wait(10)
            return b"{}"

        ingress.handle.side_effect = handle
        runtime = replace(
            runtime,
            messaging_http=runtime_module.MessagingHTTPContext(
                listen=("127.0.0.1", 0),
                evidence_ingress=ingress,
                message_ingress=ingress,
            ),
        )
        servers: list[http.server.ThreadingHTTPServer] = []
        original = daemon.create_messaging_http_server

        def create(*args: Any, **kwargs: Any) -> http.server.ThreadingHTTPServer:
            server = original(*args, **kwargs)
            servers.append(server)
            return server

        stop = threading.Event()
        read_fd, write_fd = os.pipe()

        def serve() -> None:
            try:
                daemon.serve_forever(runtime, stop=stop, ready_descriptor=write_fd)
            finally:
                returned.set()

        with patch.object(daemon, "create_messaging_http_server", side_effect=create):
            worker = threading.Thread(target=serve)
            worker.start()
            connection = None
            try:
                ready, _, _ = select.select([read_fd], [], [], 10)
                self.assertTrue(ready)
                self.assertEqual(os.read(read_fd, 6), b"READY\n")
                connection = http.client.HTTPConnection(
                    str(servers[0].server_address[0]),
                    int(servers[0].server_address[1]),
                    timeout=3,
                )
                connection.request(
                    "POST",
                    "/dm-messaging/v1/message",
                    b"{}",
                    {"Content-Type": "application/daimon+jcs"},
                )
                self.assertTrue(entered.wait(3))
                stop.set()
                self.assertFalse(
                    returned.wait(1), "daemon returned with intake still running"
                )
            finally:
                release.set()
                stop.set()
                if connection is not None:
                    connection.close()
                worker.join(timeout=10)
                os.close(read_fd)
        self.assertTrue(returned.is_set())
        self.assertFalse(worker.is_alive())

    def test_configured_messaging_listener_serves_and_closes_with_daemon(self) -> None:
        self.assertTrue(hasattr(runtime_module, "MessagingHTTPContext"))
        root, _, _ = self.make_bundle()
        runtime = load_runtime(
            root, "runtime.json", lambda: bytearray(PASSWORD), clock=lambda: NOW
        )
        ingress = Mock()
        ingress.handle.return_value = b"{}"
        runtime = replace(
            runtime,
            messaging_http=runtime_module.MessagingHTTPContext(
                listen=("127.0.0.1", 0),
                evidence_ingress=ingress,
                message_ingress=ingress,
            ),
        )
        stop = threading.Event()
        errors = []
        servers = []
        original = daemon.create_messaging_http_server

        def create(*args: Any, **kwargs: Any) -> http.server.ThreadingHTTPServer:
            server = original(*args, **kwargs)
            servers.append(server)
            return server

        read_fd, write_fd = os.pipe()

        def serve() -> None:
            try:
                daemon.serve_forever(runtime, stop=stop, ready_descriptor=write_fd)
            except Exception as exc:
                errors.append(exc)

        with patch.object(daemon, "create_messaging_http_server", side_effect=create):
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                ready, _, _ = select.select([read_fd], [], [], 10)
                self.assertTrue(ready, errors)
                self.assertEqual(os.read(read_fd, 6), b"READY\n")
                self.assertEqual(len(servers), 1)
                connection = http.client.HTTPConnection(
                    str(servers[0].server_address[0]),
                    int(servers[0].server_address[1]),
                    timeout=3,
                )
                try:
                    connection.request(
                        "POST",
                        "/dm-messaging/v1/message",
                        b"{}",
                        {"Content-Type": "application/daimon+jcs"},
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"{}")
                finally:
                    connection.close()
            finally:
                stop.set()
                worker.join(timeout=10)
                os.close(read_fd)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertFalse(runtime.socket_path.exists())
        self.assertEqual(servers[0].socket.fileno(), -1)


class NativeMessagingMcpTests(unittest.TestCase):
    def test_stdio_modes_use_authenticated_dedicated_uds(self) -> None:
        import socketserver
        import subprocess
        import sys
        import time

        from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
        from daimon_matrix.local_api import (
            authenticate_request,
            create_capability,
            create_response,
            encode_frame,
            request_hash,
        )
        from daimon_matrix.service import MESSAGING_METHODS
        from tests.test_dm025_cli_mcp import META

        now = time.time_ns() // 1_000_000
        capability = create_capability(
            _seed("mcp-only"),
            client_id="client:mcp-only",
            methods=sorted(MESSAGING_METHODS),
            not_before_ms=now - 60_000,
            not_after_ms=now + 600_000,
        )
        origin = _identity("member").origin
        runtime = {
            "runtime_id": "dm:runtime:v1:" + "n" * 43,
            "runtime_label": "mcp-test",
        }
        received: list[dict[str, Any]] = []
        errors: list[Exception] = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                try:
                    self.request.settimeout(5)
                    request = cast(dict[str, Any], daemon._receive(self.request))
                    authenticate_request(
                        request, capability, now_ms=time.time_ns() // 1_000_000
                    )
                    received.append(request)
                    response = create_response(
                        capability,
                        request_id=request["request_id"],
                        request_digest=request_hash(request),
                        server=origin,
                        runtime=runtime,
                        completed_at_ms=time.time_ns() // 1_000_000,
                        result={
                            "params": request["params"],
                            "text": "untrusted $(do-not-execute)",
                        },
                    )
                    self.request.sendall(encode_frame(response))
                except Exception as exc:
                    errors.append(exc)

        with tempfile.TemporaryDirectory(prefix="dm-mcp-") as directory:
            root = Path(directory)
            config = root / "client.json"
            config.write_bytes(
                canonical_bytes(
                    {
                        "schema": CLIENT_CONFIG_SCHEMA_V3,
                        "capability": capability.descriptor,
                        "expected_server": origin,
                        **runtime,
                    }
                )
            )
            config.chmod(0o600)
            requests = root / "requests"
            requests.mkdir(mode=0o700)
            with socketserver.UnixStreamServer(
                str(root / "rpc.sock"), Handler
            ) as server:
                (root / "rpc.sock").chmod(0o600)
                worker = threading.Thread(target=server.serve_forever)
                worker.start()
                try:
                    for legacy in (False, True):
                        with self.subTest(legacy=legacy):
                            read_fd, write_fd = os.pipe()
                            os.write(write_fd, capability.key)
                            os.close(write_fd)
                            try:
                                process = subprocess.Popen(
                                    [
                                        sys.executable,
                                        "-m",
                                        "daimon_matrix.mcp_server",
                                        "--messaging-only",
                                        "--socket",
                                        str(root / "rpc.sock"),
                                        "--client-config",
                                        str(config),
                                        "--capability-key-fd",
                                        str(read_fd),
                                        "--request-dir",
                                        str(requests),
                                    ],
                                    cwd=ROOT,
                                    env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                                    pass_fds=(read_fd,),
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                )
                            finally:
                                os.close(read_fd)
                            assert (
                                process.stdin is not None
                                and process.stdout is not None
                                and process.stderr is not None
                            )
                            try:

                                def exchange(
                                    method: str,
                                    params: dict[str, Any],
                                    process: subprocess.Popen[bytes] = process,
                                    legacy: bool = legacy,
                                ) -> dict[str, Any]:
                                    assert (
                                        process.stdin is not None
                                        and process.stdout is not None
                                    )
                                    frame = {
                                        "jsonrpc": "2.0",
                                        "id": method,
                                        "method": method,
                                        "params": params
                                        if legacy or method == "initialize"
                                        else {"_meta": META, **params},
                                    }
                                    process.stdin.write(canonical_bytes(frame) + b"\n")
                                    process.stdin.flush()
                                    ready, _, _ = select.select(
                                        [process.stdout], [], [], 10
                                    )
                                    self.assertTrue(ready, "stdio timeout")
                                    raw = process.stdout.readline()
                                    self.assertTrue(raw, "stdio exited before replying")
                                    return cast(dict[str, Any], json.loads(raw))

                                if legacy:
                                    result = exchange(
                                        "initialize",
                                        {
                                            "protocolVersion": "2025-06-18",
                                            "capabilities": {},
                                            "clientInfo": {
                                                "name": "test",
                                                "version": "1",
                                            },
                                        },
                                    )
                                    self.assertEqual(
                                        result["result"]["protocolVersion"],
                                        "2025-06-18",
                                    )
                                    process.stdin.write(
                                        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                                    )
                                    process.stdin.flush()
                                result = exchange("tools/list", {})
                                self.assertEqual(
                                    {t["name"] for t in result["result"]["tools"]},
                                    {
                                        "messaging_" + method
                                        for method in (
                                            "inbox",
                                            "send",
                                            "reply",
                                            "delivery",
                                        )
                                    },
                                )
                                for method, args in {
                                    "inbox": {"channel_id": "incoming"},
                                    "send": {
                                        "channel_id": "outgoing",
                                        "send_id": _uuid("stdio-send"),
                                        "thread_id": _uuid("stdio-thread"),
                                        "text": "untrusted",
                                    },
                                    "reply": {
                                        "channel_id": "outgoing",
                                        "received_channel_id": "incoming",
                                        "send_id": _uuid("stdio-reply"),
                                        "message_id": _uuid("stdio-message"),
                                        "text": "untrusted",
                                    },
                                    "delivery": {
                                        "channel_id": "outgoing",
                                        "send_id": _uuid("stdio-send"),
                                    },
                                }.items():
                                    result = exchange(
                                        "tools/call",
                                        {
                                            "name": "messaging_" + method,
                                            "arguments": args,
                                        },
                                    )
                                    self.assertFalse(result["result"]["isError"])
                                    public = json.loads(
                                        result["result"]["content"][0]["text"]
                                    )
                                    self.assertNotIn("auth", public)
                                    self.assertEqual(
                                        received[-1]["method"], "messaging." + method
                                    )
                                    self.assertEqual(
                                        public["result"]["params"],
                                        {"after": 0, "limit": 100, **args}
                                        if method == "inbox"
                                        else args,
                                    )
                                count = len(received)
                                for name, bad_args in (
                                    ("scope_me", {}),
                                    (
                                        "messaging_inbox",
                                        {"channel_id": "incoming", "limit": True},
                                    ),
                                    ("messaging_send", {"endpoint": "evil"}),
                                ):
                                    self.assertIn(
                                        "error",
                                        exchange(
                                            "tools/call",
                                            {"name": name, "arguments": bad_args},
                                        ),
                                    )
                                self.assertIn(
                                    "error",
                                    exchange(
                                        "resources/read", {"uri": "daimon:scope/me"}
                                    ),
                                )
                                self.assertEqual(len(received), count)
                            finally:
                                if process.stdin is not None:
                                    process.stdin.close()
                                try:
                                    process.wait(timeout=10)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait(timeout=5)
                                stderr = process.stderr.read()
                                process.stdout.close()
                                process.stderr.close()
                            self.assertEqual(process.returncode, 0, stderr)
                    self.assertEqual(len(received), 8)
                    self.assertEqual(errors, [])
                finally:
                    server.shutdown()
                    worker.join(timeout=5)

    def test_typed_calls_validate_before_io(self) -> None:
        import asyncio

        import mcp_types as types
        from mcp.shared.exceptions import MCPError

        from daimon_matrix.mcp_server import DaimonMcp

        cases: dict[str, dict[str, Any]] = {
            "messaging_inbox": {"channel_id": "incoming", "after": 0, "limit": 100},
            "messaging_send": {
                "channel_id": "outgoing",
                "send_id": _uuid("mcp-send"),
                "thread_id": _uuid("mcp-thread"),
                "text": "$(untrusted)",
            },
            "messaging_reply": {
                "channel_id": "outgoing",
                "received_channel_id": "incoming",
                "send_id": _uuid("mcp-reply"),
                "message_id": _uuid("mcp-message"),
                "text": "inert data",
            },
            "messaging_delivery": {
                "channel_id": "outgoing",
                "send_id": _uuid("mcp-send"),
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.send.return_value = {"ok": True, "result": {}, "auth": "secret"}
            adapter = DaimonMcp(client, Path(directory), messaging_only=True)
            for name, args in cases.items():
                with self.subTest(name=name):
                    result = asyncio.run(
                        adapter.call_tool(
                            Mock(),
                            types.CallToolRequestParams(name=name, arguments=args),
                        )
                    )
                    self.assertFalse(result.is_error)
                    self.assertNotIn("auth", result.structured_content)
                    client.prepare.assert_called_with(name.replace("_", ".", 1), args)
                    client.reset_mock()
                    invalid: list[dict[str, Any]] = [
                        {**args, "endpoint": "https://evil"},
                        {**args, "operation_id": None},
                    ]
                    invalid_types: tuple[Any, ...] = (None, True, [], {})
                    for field in args:
                        invalid.extend({**args, field: bad} for bad in invalid_types)
                    invalid += [{**args, "channel_id": "bad\n"}]
                    for field in ("send_id", "thread_id", "message_id"):
                        if field in args:
                            invalid.extend(
                                {**args, field: bad}
                                for bad in (
                                    "not-uuid",
                                    args[field].upper(),
                                    args[field].replace("-", ""),
                                )
                            )
                    if "text" in args:
                        invalid.extend(
                            {**args, "text": bad} for bad in ("", "x" * 16385)
                        )
                    if name == "messaging_inbox":
                        invalid.extend(
                            {**args, **bad}
                            for bad in (
                                {"after": -1},
                                {"after": 2**53},
                                {"limit": 0},
                                {"limit": 101},
                                {"limit": 1.5},
                            )
                        )
                    for bad in invalid:
                        with self.subTest(bad=bad), self.assertRaises(MCPError):
                            asyncio.run(
                                adapter.call_tool(
                                    Mock(),
                                    types.CallToolRequestParams(
                                        name=name, arguments=bad
                                    ),
                                )
                            )
                    client.prepare.assert_not_called()
                    client.send.assert_not_called()
            asyncio.run(
                adapter.call_tool(
                    Mock(),
                    types.CallToolRequestParams(
                        name="messaging_inbox", arguments={"channel_id": "incoming"}
                    ),
                )
            )
            client.prepare.assert_called_with(
                "messaging.inbox", cases["messaging_inbox"]
            )

    def test_closed_mode_selection(self) -> None:
        import asyncio

        import mcp_types as types
        from mcp.shared.exceptions import MCPError

        from daimon_matrix.mcp_server import TOOL_CONTRACTS, DaimonMcp

        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.config.expected_server = {}
            narrow = DaimonMcp(client, Path(directory), messaging_only=True)
            ordinary = DaimonMcp(client, Path(directory))
            expected = {
                "messaging_inbox",
                "messaging_send",
                "messaging_reply",
                "messaging_delivery",
            }
            tools = asyncio.run(narrow.list_tools(Mock(), None))
            self.assertEqual({tool.name for tool in tools.tools}, expected)
            self.assertEqual(
                {
                    tool.name
                    for tool in asyncio.run(ordinary.list_tools(Mock(), None)).tools
                },
                set(TOOL_CONTRACTS),
            )
            self.assertFalse(expected & set(TOOL_CONTRACTS))
            for tool in tools.tools:
                assert tool.description is not None and tool.annotations is not None
                self.assertIn("untrusted", tool.description)
                self.assertIn("no execution authority", tool.description)
                self.assertEqual(
                    tool.annotations.read_only_hint,
                    tool.name in {"messaging_inbox", "messaging_delivery"},
                )
                self.assertEqual(
                    tool.annotations.open_world_hint,
                    tool.name in {"messaging_send", "messaging_reply"},
                )
                self.assertFalse(tool.input_schema["additionalProperties"])
            resources = asyncio.run(narrow.list_resources(Mock(), None))
            self.assertEqual(
                {str(r.uri) for r in resources.resources},
                {
                    "daimon:contract/server",
                    "daimon:contract/tools",
                    "daimon:contract/local-api",
                },
            )
            for uri in ("daimon:contract/tools", "daimon:contract/local-api"):
                result = asyncio.run(
                    narrow.read_resource(
                        Mock(), types.ReadResourceRequestParams(uri=uri)
                    )
                )
                assert isinstance(result.contents[0], types.TextResourceContents)
                text = result.contents[0].text
                self.assertNotIn("scope.me", text)
                self.assertIn("messaging.inbox", text)
            for name in TOOL_CONTRACTS:
                with self.assertRaises(MCPError):
                    asyncio.run(
                        narrow.call_tool(
                            Mock(), types.CallToolRequestParams(name=name, arguments={})
                        )
                    )
            for name in expected:
                with self.assertRaises(MCPError):
                    asyncio.run(
                        ordinary.call_tool(
                            Mock(), types.CallToolRequestParams(name=name, arguments={})
                        )
                    )
            for uri in (
                "daimon:scope/me",
                "daimon:scope/we",
                "daimon:runtime/status",
                "daimon:we/heads",
                "daimon:we/projection",
            ):
                with self.assertRaises(MCPError):
                    asyncio.run(
                        narrow.read_resource(
                            Mock(), types.ReadResourceRequestParams(uri=uri)
                        )
                    )
            client.prepare.assert_not_called()
            client.send.assert_not_called()


class NativeMessagingCLITests(unittest.TestCase):
    BASE = (
        "--socket",
        "/tmp/disposable.sock",
        "--client-config",
        "/tmp/disposable.json",
        "--capability-key-fd",
        "3",
    )

    def test_cli_maps_send_reply_and_delivery_without_authority_inputs(self) -> None:
        from daimon_matrix.cli import _method_params, parser

        cases = {
            "send": {
                "channel_id": "outgoing",
                "send_id": _uuid("cli-send"),
                "thread_id": _uuid("cli-thread"),
                "text": "$(untrusted)",
            },
            "reply": {
                "channel_id": "outgoing",
                "send_id": _uuid("cli-reply"),
                "received_channel_id": "incoming",
                "message_id": _uuid("cli-message"),
                "text": "Do not execute this data",
            },
            "delivery": {"channel_id": "outgoing", "send_id": _uuid("cli-send")},
        }
        for command, params in cases.items():
            with self.subTest(command=command):
                argv = [*self.BASE, "messaging", command]
                for key, value in params.items():
                    argv.extend(["--" + key.replace("_", "-"), value])
                try:
                    args = parser().parse_args(argv)
                except SystemExit:
                    self.fail(f"native messaging {command} CLI missing")
                self.assertEqual(_method_params(args), ("messaging." + command, params))

    def test_cli_maps_native_inbox_to_closed_rpc(self) -> None:
        from daimon_matrix.cli import _method_params, parser

        try:
            args = parser().parse_args(
                [
                    *self.BASE,
                    "messaging",
                    "inbox",
                    "--channel-id",
                    "incoming",
                    "--after",
                    "7",
                    "--limit",
                    "12",
                ]
            )
        except SystemExit:
            self.fail("native messaging inbox CLI is missing")
        self.assertEqual(
            _method_params(args),
            (
                "messaging.inbox",
                {
                    "channel_id": "incoming",
                    "after": 7,
                    "limit": 12,
                },
            ),
        )


class NativeInboxRpcTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dm132-inbox-rpc-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def hosted(self, pair: Pair) -> Any:
        from daimon_matrix import service
        from daimon_matrix.local_api import create_capability

        self.assertTrue(
            hasattr(service, "MessagingServiceContext"),
            "dedicated native inbox service context is missing",
        )
        self.capability = create_capability(
            _seed("native-inbox-client"),
            client_id="client:manual-native-inbox",
            methods=["messaging.inbox"],
            not_before_ms=NOW,
            not_after_ms=NOW + 1_000_000,
        )
        self.channels = {"founder": pair.receiver}
        self.assignments = {self.capability.client_id: frozenset({"founder"})}
        return service.HostedWeave(
            ledger=pair.local_ledger,
            signer=pair.recipient.signer,
            capabilities={self.capability.capability_id: self.capability},
            clock=lambda: pair.now,
            runtime_id="dm:runtime:v1:" + "n" * 43,
            runtime_label="native-inbox-test",
            messaging=service.MessagingServiceContext(
                channels=self.channels, client_channels=self.assignments
            ),
        )

    def request(self, pair: Pair, label: str, **params: Any) -> dict[str, Any]:
        from daimon_matrix.local_api import create_request

        return create_request(
            self.capability,
            request_id=_uuid("inbox-rpc:" + label),
            issued_at_ms=pair.now,
            method="messaging.inbox",
            params={"channel_id": "founder", "after": 0, "limit": 10, **params},
        )

    def invoke(self, hosted: Any, request: dict[str, Any]) -> dict[str, Any]:
        from daimon_matrix.local_api import request_hash, verify_response

        return verify_response(
            hosted.handle(request),
            self.capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=hosted.origin,
            expected_runtime=hosted.runtime_identity,
        )

    def assert_rejected(
        self, hosted: Any, request: dict[str, Any], code: str = "messaging_rejected"
    ) -> None:
        response = self.invoke(hosted, request)
        self.assertFalse(response["ok"], "inbox plaintext survived authorization loss")
        self.assertIsNone(response["result"])
        self.assertEqual(response["error"], {"code": code, "retryable": False})
        self.assertNotIn(TEXT, json.dumps(response))

    def test_local_client_supports_dedicated_inbox_without_broad_roles(self) -> None:
        from daimon_matrix.client import ClientConfig, ClientError, LocalClient
        from daimon_matrix.service import SERVICE_METHODS

        pair = Pair(self.root)
        hosted = self.hosted(pair)
        client = LocalClient(
            self.root / "absent.sock",
            ClientConfig(
                self.capability, hosted.origin, hosted.runtime_id, hosted.runtime_label
            ),
            clock=lambda: pair.now,
        )
        request = client.prepare(
            "messaging.inbox",
            {
                "channel_id": "founder",
                "after": 0,
                "limit": 1,
            },
        )
        self.assertEqual(request["method"], "messaging.inbox")
        self.assertNotIn("messaging.inbox", SERVICE_METHODS)
        # Exact retry must pass the same method gate and reach the socket check.
        with self.assertRaisesRegex(ClientError, "daemon_unavailable"):
            client.send(request)

    def test_cached_inbox_rechecks_real_signed_grant_revocation(self) -> None:
        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        request = self.request(pair, "revoked-cache")
        self.assertTrue(self.invoke(hosted, request)["ok"])
        pair.receiver_relationships.ingest(
            next(
                event
                for event in pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        pair.now = NOW + 17
        before = pair.store_path.read_bytes()
        self.assert_rejected(hosted, request)
        self.assert_rejected(hosted, self.request(pair, "revoked-fresh"))
        self.assertEqual(pair.store_path.read_bytes(), before)
        self.assertEqual(pair.local_ledger.events(), [])
        control = Pair(self.root / "fresh-control")
        evidence, message, _, _ = control.wire()
        control.receiver.receive_evidence(evidence)
        control.receiver.receive_message(message)
        fresh_host = self.hosted(control)
        self.assertTrue(self.invoke(fresh_host, self.request(control, "control"))["ok"])

    def test_cached_inbox_rechecks_client_assignment(self) -> None:
        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        request = self.request(pair, "assignment-cache")
        self.assertTrue(self.invoke(hosted, request)["ok"])
        for index, assignment in enumerate((frozenset(), frozenset({"other"}))):
            with self.subTest(assignment=assignment):
                self.assignments[self.capability.client_id] = assignment
                self.assert_rejected(hosted, request)
                self.assert_rejected(hosted, self.request(pair, f"unassigned-{index}"))
        del self.assignments[self.capability.client_id]
        self.assert_rejected(hosted, request)
        self.assignments[self.capability.client_id] = frozenset({"founder"})
        self.assertTrue(
            self.invoke(hosted, self.request(pair, "reassigned-control"))["ok"]
        )

    def test_cached_inbox_rejects_valid_changed_channel_policy_or_store(self) -> None:
        from dataclasses import replace

        from daimon_matrix.messaging_store import MessagingInboxStore

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        request = self.request(pair, "policy-cache")
        original = self.invoke(hosted, request)
        self.assertTrue(original["ok"])
        replacement = copy.copy(pair.receiver)
        replacement.policy = replace(pair.policy, max_ttl_ms=59_999)
        self.assertNotEqual(
            replacement._policy_hash(pair.now), original["result"]["policy_hash"]
        )
        replacement_store = copy.copy(pair.receiver)
        replacement_store.inbox = MessagingInboxStore(self.root / "other-inbox.sqlite3")
        for index, channel in enumerate((replacement, replacement_store)):
            with self.subTest(remapping=index):
                self.channels["founder"] = channel
                # Both replacements remain independently authorized, but neither
                # owns the old page. A fresh RPC may read its actual empty inbox.
                fresh = self.invoke(hosted, self.request(pair, f"remapped-{index}"))
                self.assertTrue(fresh["ok"], fresh["error"])
                self.assertEqual(fresh["result"]["items"], [])
                self.assert_rejected(hosted, request)
        self.channels["founder"] = pair.receiver
        self.assertEqual(self.invoke(hosted, request), original)
        self.assertEqual(pair.local_ledger.events(), [])

    def test_inbox_params_are_closed_and_bounded(self) -> None:
        from daimon_matrix.local_api import create_request

        pair = Pair(self.root)
        hosted = self.hosted(pair)
        valid: dict[str, Any] = {"channel_id": "founder", "after": 0, "limit": 10}
        invalid = [
            {key: value for key, value in valid.items() if key != field}
            for field in valid
        ]
        invalid_fields: tuple[tuple[str, tuple[Any, ...]], ...] = (
            ("channel_id", (None, False, 1, [], {}, "", "x" * 129, "../founder")),
            ("after", (None, False, True, -1, "0", [], {})),
            ("limit", (None, False, True, 0, 101, "10", [], {})),
        )
        invalid.extend(
            {**valid, field: value}
            for field, values in invalid_fields
            for value in values
        )
        invalid.extend(
            {**valid, field: "not-model-authority"}
            for field in ("authority", "grant", "key", "endpoint", "unexpected")
        )
        for index, params in enumerate(invalid):
            with self.subTest(params=params):
                request = create_request(
                    self.capability,
                    request_id=_uuid(f"invalid-inbox:{index}"),
                    issued_at_ms=pair.now,
                    method="messaging.inbox",
                    params=params,
                )
                self.assert_rejected(hosted, request, "invalid_params")
                self.assert_rejected(hosted, request, "invalid_params")
        for channel_id in ("unknown", "other"):
            self.assert_rejected(
                hosted, self.request(pair, channel_id, channel_id=channel_id)
            )
        for index, bounds in enumerate(((0, 1), (2**53 - 1, 100))):
            result = self.invoke(
                hosted,
                self.request(
                    pair, f"valid-bound:{index}", after=bounds[0], limit=bounds[1]
                ),
            )
            self.assertTrue(result["ok"], result["error"])
            self.assertEqual(result["result"]["items"], [])

    def test_context_requires_exact_host_binding_and_assigned_dedicated_clients(
        self,
    ) -> None:
        from dataclasses import replace

        from daimon_matrix.service import MessagingServiceContext, ServiceError

        pair = Pair(self.root)
        hosted = self.hosted(pair)
        assert hosted.messaging is not None
        wrong_being = copy.copy(pair.receiver)
        wrong_being.local_being_ref = pair.sender.state.being_ref
        wrong_being.local_credential_id = pair.sender.credential["artifact_id"]
        wrong_credential = copy.copy(pair.receiver)
        wrong_credential.local_credential_id = pair.sender.credential["artifact_id"]
        wrong_resolver = copy.copy(pair.receiver)
        wrong_resolver.authority_resolver = lambda _: pair.sender.authority
        # Deliberately bypass static types to exercise the construction boundary.
        invalid_assignment: Any = "founder"
        invalid_channel: Any = object()
        contexts: list[Any] = [
            {},
            MessagingServiceContext({}, self.assignments),
            MessagingServiceContext(self.channels, {}),
            MessagingServiceContext(
                self.channels, {self.capability.client_id: frozenset()}
            ),
            MessagingServiceContext(
                self.channels, {"unknown-client": frozenset({"founder"})}
            ),
            MessagingServiceContext(
                self.channels, {self.capability.client_id: frozenset({"unknown"})}
            ),
            MessagingServiceContext(
                self.channels, {self.capability.client_id: invalid_assignment}
            ),
            MessagingServiceContext({"../founder": pair.receiver}, self.assignments),
            MessagingServiceContext({"founder": invalid_channel}, self.assignments),
        ]
        contexts.extend(
            MessagingServiceContext({"founder": channel}, self.assignments)
            for channel in (wrong_being, wrong_credential, wrong_resolver)
        )
        contexts.append(
            MessagingServiceContext(
                {**self.channels, "unselected": wrong_being}, self.assignments
            )
        )
        for index, context in enumerate(contexts):
            with self.subTest(context=index), self.assertRaises(ServiceError):
                replace(hosted, messaging=context)
        foreign_ledger = Ledger(
            self.root / "foreign-host.sqlite3",
            authority=pair.sender.authority,
            local_origin=pair.sender.origin,
            clock=lambda: pair.now,
        )
        with self.assertRaises(ServiceError):
            replace(
                hosted,
                ledger=foreign_ledger,
                signer=pair.sender.signer,
                communication=None,
                scopes=None,
                curator=None,
                review=None,
            )
        request = self.request(pair, "binding-cache")
        self.assertTrue(self.invoke(hosted, request)["ok"])
        # Even an unselected channel must not let a mutated invalid context keep
        # serving a previously valid cache entry.
        self.channels["unselected"] = wrong_being
        self.assert_rejected(hosted, request)
        self.assert_rejected(hosted, self.request(pair, "binding-fresh"))
        del self.channels["unselected"]
        self.assertTrue(
            self.invoke(hosted, self.request(pair, "binding-control"))["ok"]
        )

    def test_authorized_oversized_page_returns_small_authenticated_error(self) -> None:
        from daimon_matrix.local_api import (
            MAX_FRAME_BYTES,
            create_response,
            encode_frame,
            request_hash,
        )

        pair = Pair(self.root)
        for index in range(12):
            # Escaped text is within each signed event's text/body bounds but
            # its canonical JSON expansion makes this count-bounded page huge.
            evidence, message, _, _ = pair.wire(
                100 + index * 10, text=TEXT + "\x01" * 31_000
            )
            pair.receiver.receive_evidence(evidence)
            pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        page = pair.receiver.page(after=0, limit=100)
        self.assertGreater(len(canonical_bytes(page)), MAX_FRAME_BYTES)
        oversized = self.request(pair, "oversized", limit=100)
        self.assert_rejected(hosted, oversized, "messaging_page_too_large")
        retry = self.invoke(hosted, oversized)
        self.assertEqual(retry["error"]["code"], "messaging_page_too_large")
        self.assertLess(len(encode_frame(retry)), 2048)
        reduced = self.invoke(hosted, self.request(pair, "reduced", limit=1))
        self.assertTrue(reduced["ok"], reduced["error"])
        self.assertEqual(len(reduced["result"]["items"]), 1)
        self.assertLess(len(encode_frame(reduced)), MAX_FRAME_BYTES)
        # A genuine HMAC cache from an older unbounded implementation is not
        # permission to emit a frame the local protocol cannot carry.
        cached_request = self.request(pair, "oversized-old-cache", limit=100)
        identity = dict(
            client_id=self.capability.client_id,
            request_id=cached_request["request_id"],
            request_hash=request_hash(cached_request),
            method="messaging.inbox",
        )
        pair.local_ledger.begin_rpc(**identity)
        pair.local_ledger.finish_rpc(
            **identity,
            response=create_response(
                self.capability,
                request_id=cached_request["request_id"],
                request_digest=request_hash(cached_request),
                server=hosted.origin,
                runtime=hosted.runtime_identity,
                completed_at_ms=pair.now,
                result={
                    "channel_id": "founder",
                    "items": page,
                    "policy_hash": pair.receiver._policy_hash(pair.now),
                },
            ),
        )
        self.assert_rejected(hosted, cached_request, "messaging_page_too_large")
        self.assertEqual(pair.local_ledger.events(), [])

    def test_inbox_rechecks_policy_changes_during_page_and_journal_finish(self) -> None:
        from dataclasses import replace
        from unittest.mock import patch

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        original_page = pair.receiver.page
        changed_policy = replace(pair.policy, max_ttl_ms=59_999)

        def change_after_page(*, after: int, limit: int) -> list[dict[str, Any]]:
            rows = original_page(after=after, limit=limit)
            pair.receiver.policy = changed_policy
            return rows

        with patch.object(pair.receiver, "page", side_effect=change_after_page):
            self.assert_rejected(hosted, self.request(pair, "changed-during-page"))
        pair.receiver.policy = pair.policy
        finish = pair.local_ledger.finish_rpc

        def change_after_finish(**kwargs: Any) -> dict[str, Any]:
            response = finish(**kwargs)
            self.assignments[self.capability.client_id] = frozenset()
            return response

        with patch.object(
            pair.local_ledger, "finish_rpc", side_effect=change_after_finish
        ):
            self.assert_rejected(hosted, self.request(pair, "changed-during-finish"))
        self.assignments[self.capability.client_id] = frozenset({"founder"})
        control = self.invoke(hosted, self.request(pair, "post-change-control"))
        self.assertTrue(control["ok"], control["error"])
        self.assertEqual(len(control["result"]["items"]), 1)

    def test_inbox_preserves_rpc_auth_conflicts_and_historical_page_retry(self) -> None:
        from daimon_matrix.canonical import CanonicalError
        from daimon_matrix.local_api import LocalApiError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        hosted = self.hosted(pair)
        request = self.request(pair, "stable")
        response = self.invoke(hosted, request)
        self.assertTrue(response["ok"])
        tampered = copy.deepcopy(request)
        tampered["params"]["limit"] = 1
        with self.assertRaisesRegex(LocalApiError, "^authentication_failed$"):
            hosted.handle(tampered)
        self.assert_rejected(
            hosted, self.request(pair, "stable", limit=1), "request_conflict"
        )
        evidence, message, _, _ = pair.wire(200)
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(self.invoke(hosted, request), response)
        fresh = self.invoke(hosted, self.request(pair, "new-page"))
        self.assertEqual(len(fresh["result"]["items"]), 2)
        with self.assertRaises(CanonicalError):
            self.request(pair, "too-large-cursor", after=2**53)
        stale_unseen = self.request(pair, "stale-unseen")
        pair.now = NOW + 31_011
        self.assertEqual(self.invoke(hosted, request), response)
        with self.assertRaisesRegex(LocalApiError, "^authentication_failed$"):
            hosted.handle(stale_unseen)
        pair.now = NOW + 1_000_000
        with self.assertRaisesRegex(LocalApiError, "^authentication_failed$"):
            hosted.handle(request)
        self.assertEqual(pair.local_ledger.events(), [])

    def test_genuine_receive_then_dedicated_authenticated_manual_inbox(self) -> None:
        from dataclasses import replace

        from daimon_matrix import service
        from daimon_matrix.local_api import create_capability

        pair = Pair(self.root)
        evidence, wire, message, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(wire)
        before = pair.store_path.read_bytes()
        hosted = self.hosted(pair)
        request = self.request(pair, "positive")
        response = self.invoke(hosted, request)
        self.assertTrue(response["ok"], response["error"])
        self.assertEqual(
            response["result"],
            {
                "channel_id": "founder",
                "items": pair.receiver.page(after=0, limit=10),
                "policy_hash": pair.receiver._policy_hash(pair.now),
            },
        )
        self.assertEqual(response["result"]["items"][0]["message"], message)
        self.assertEqual(self.invoke(hosted, request), response)
        self.assertEqual(pair.store_path.read_bytes(), before)
        self.assertEqual(pair.local_ledger.events(), [])
        self.assertEqual(
            service.MESSAGING_METHODS,
            frozenset(
                {
                    "messaging.inbox",
                    "messaging.send",
                    "messaging.reply",
                    "messaging.delivery",
                }
            ),
        )
        self.assertFalse(service.MESSAGING_METHODS & service.SERVICE_METHODS)
        with self.assertRaises(service.ServiceError):
            replace(hosted, messaging=None)
        mixed = create_capability(
            _seed("native-mixed-client"),
            client_id=self.capability.client_id,
            methods=["messaging.inbox", "we.observe"],
            not_before_ms=NOW,
            not_after_ms=NOW + 1000,
        )
        with self.assertRaises(service.ServiceError):
            replace(hosted, capabilities={mixed.capability_id: mixed})


class NativeSendRpcTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dm132-send-rpc-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def setup_sender(self) -> tuple[Any, Any, Any, list[Any]]:
        from daimon_matrix import service
        from daimon_matrix.local_api import create_capability
        from daimon_matrix.messaging import MessagingDelivery

        pair = Pair(self.root)
        sender = NativeMessagingTests.make_sender(cast(Any, self), pair)
        self.send_id = _uuid("native-rpc-send")
        evidence, message, calls = NativeMessagingTests.delivery_transports(
            cast(Any, self), pair, sender, self.send_id
        )
        delivery = MessagingDelivery(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        self.capability = create_capability(
            _seed("native-send-client"),
            client_id="client:native-send",
            methods=["messaging.send"],
            not_before_ms=NOW,
            not_after_ms=NOW + 1_000_000,
        )
        self.assignments = {self.capability.client_id: frozenset({"member"})}
        self.assertIn(
            "deliveries", service.MessagingServiceContext.__dataclass_fields__
        )
        self.context = service.MessagingServiceContext(
            channels={},
            deliveries={"member": delivery},
            client_channels=self.assignments,
        )
        hosted = service.HostedWeave(
            ledger=sender.ledger,
            signer=pair.sender.signer,
            capabilities={self.capability.capability_id: self.capability},
            clock=lambda: pair.now,
            runtime_id="dm:runtime:v1:" + "s" * 43,
            runtime_label="native-send-test",
            messaging=self.context,
        )
        return pair, hosted, delivery, calls

    def request(self, pair: Pair, **changes: Any) -> dict[str, Any]:
        from daimon_matrix.local_api import create_request

        return create_request(
            self.capability,
            request_id=_uuid("send-rpc:" + str(changes)),
            issued_at_ms=pair.now,
            method="messaging.send",
            params={
                "channel_id": "member",
                "send_id": self.send_id,
                "thread_id": _uuid("native-rpc-thread"),
                "text": TEXT,
                **changes,
            },
        )

    def invoke(self, hosted: Any, request: dict[str, Any]) -> dict[str, Any]:
        return NativeInboxRpcTests.invoke(cast(Any, self), hosted, request)

    def reverse_channel(self, pair: Pair) -> Any:
        from dataclasses import replace

        from daimon_matrix.canonical import b64url
        from daimon_matrix.messaging import GrantReference, MessagingChannel
        from daimon_matrix.messaging_store import MessagingInboxStore
        from daimon_matrix.relationships import (
            grant_id,
            relationship_event_subject,
        )

        def append(
            identity: Any, kind: str, payload: dict[str, Any], label: str
        ) -> Any:
            event = create_event(
                identity.authority,
                identity.origin,
                identity.signer,
                event_id=_uuid("reverse:" + label),
                sequence=100 + len(events),
                previous_event_id=_uuid("reverse:previous:" + label),
                occurred_at_ms=payload.get(
                    "issued_at_ms", payload.get("accepted_at_ms", NOW + 8)
                ),
                causal_parents=(),
                kind=kind,
                subject=relationship_event_subject(kind, payload),
                payload=payload,
                sensitivity="shareable",
            )
            for store in (pair.sender_relationships, pair.receiver_relationships):
                store.ingest(event)
            events.append(event)
            return event

        events: list[Any] = []
        resource = pair.policy.resource_ref
        nonce = b64url(_seed("reverse-grant"))
        identifier = grant_id(
            nonce=nonce,
            relationship=pair.policy.relationship_id,
            grantor_being_ref=pair.recipient.state.being_ref,
            subject_being_ref=pair.sender.state.being_ref,
        )
        grant = append(
            pair.recipient,
            "matrix/relationship-grant",
            {
                **pair.grant["payload"],
                "grant_id": identifier,
                "nonce": nonce,
                "grantor_being_ref": pair.recipient.state.being_ref,
                "subject_being_ref": pair.sender.state.being_ref,
                "issued_at_ms": NOW + 8,
                "parent_grant_ref": {
                    "event_id": pair.grant["event_id"],
                    "event_hash": pair.grant["content_hash"],
                },
                "permissions": [
                    {
                        **pair.grant["payload"]["permissions"][0],
                        "resource_ref": resource,
                        "delegable": False,
                        "remaining_delegation_depth": 0,
                    }
                ],
            },
            "grant",
        )
        append(
            pair.sender,
            "matrix/relationship-grant-acceptance",
            {
                "schema": "dm.relationship.grant-acceptance/v1",
                "grant_id": identifier,
                "grant_ref": {
                    "event_id": grant["event_id"],
                    "event_hash": grant["content_hash"],
                },
                "relationship_id": pair.policy.relationship_id,
                "grantor_being_ref": pair.recipient.state.being_ref,
                "subject_being_ref": pair.sender.state.being_ref,
                "accepted_at_ms": NOW + 9,
            },
            "acceptance",
        )
        snapshot = pair.sender_relationships.view(
            at_ms=pair.now, card_verifier=pair.receiver._card
        ).snapshot(pair.policy.tribe_ref)
        member = next(
            m
            for m in snapshot.value["members"]
            if m["principal_id"] == pair.sender.state.being_ref
        )
        policy = replace(
            pair.policy,
            peer_being_ref=pair.recipient.state.being_ref,
            peer_embodiment_id=pair.recipient.origin["embodiment_id"],
            peer_credential_id=pair.recipient.credential["artifact_id"],
            membership_ref=member["membership_ref"],
            resource_ref=resource,
            grant_refs=(
                GrantReference(identifier, grant["event_id"], grant["content_hash"]),
            ),
        )
        self.reverse_grant = grant
        return MessagingChannel(
            policy=policy,
            local_being_ref=pair.sender.state.being_ref,
            local_credential_id=pair.sender.credential["artifact_id"],
            authority_resolver=lambda ref: pair.public[ref],
            custody=pair.sender_custody,
            relationships=pair.sender_relationships,
            inbox=MessagingInboxStore(self.root / "sender/replies.sqlite3"),
            clock=lambda: pair.now,
        )

    def test_application_response_uses_exact_received_context_and_reverse_grant(
        self,
    ) -> None:
        from types import SimpleNamespace

        from daimon_matrix.local_api import create_capability, create_request
        from daimon_matrix.messaging import (
            MessagingChannel,
            MessagingDelivery,
            MessagingSender,
        )
        from daimon_matrix.messaging_store import (
            MessagingInboxStore,
            MessagingOutboxStore,
        )
        from daimon_matrix.service import HostedWeave, MessagingServiceContext

        pair, forward_host, _, _ = self.setup_sender()
        reverse_receiver = self.reverse_channel(pair)
        forward = self.invoke(forward_host, self.request(pair))
        self.assertTrue(forward["ok"], forward)
        received = pair.receiver.page(after=0, limit=1)[0]["message"]
        reverse_context = MessagingChannel(
            policy=reverse_receiver.policy,
            local_being_ref=pair.sender.state.being_ref,
            local_credential_id=pair.sender.credential["artifact_id"],
            authority_resolver=lambda ref: pair.public[ref],
            custody=pair.receiver_custody,
            relationships=pair.receiver_relationships,
            inbox=MessagingInboxStore(self.root / "receiver/unused.sqlite3"),
            clock=lambda: pair.now,
        )
        sender = MessagingSender(
            context=reverse_context,
            ledger=pair.local_ledger,
            signer=pair.recipient.signer,
            custody=pair.receiver_custody,
            outbox=MessagingOutboxStore(self.root / "receiver/replies-outbox.sqlite3"),
            clock=lambda: pair.now,
        )
        self.send_id = _uuid("application-response")
        reverse_pair = SimpleNamespace(
            receiver=reverse_receiver,
            policy=reverse_receiver.policy,
            recipient=pair.sender,
            sender=pair.recipient,
            now=pair.now,
        )
        # Distinct opaque transport stores for the reverse path.
        old_root = self.root
        self.root = old_root / "reverse-transport"
        self.root.mkdir(mode=0o700)
        (self.root / "receiver").mkdir(mode=0o700)
        evidence, message, calls = NativeMessagingTests.delivery_transports(
            cast(Any, self), cast(Any, reverse_pair), sender, self.send_id
        )
        self.root = old_root
        delivery = MessagingDelivery(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="b" * 64,
        )
        self.capability = create_capability(
            _seed("reply-client"),
            client_id="client:reply",
            methods=["messaging.reply", "messaging.delivery"],
            not_before_ms=NOW,
            not_after_ms=NOW + 1_000_000,
        )
        self.assignments = {
            self.capability.client_id: frozenset({"incoming", "outgoing"})
        }
        try:
            hosted = HostedWeave(
                ledger=pair.local_ledger,
                signer=pair.recipient.signer,
                capabilities={self.capability.capability_id: self.capability},
                clock=lambda: pair.now,
                runtime_id="dm:runtime:v1:" + "r" * 43,
                runtime_label="reply-test",
                messaging=MessagingServiceContext(
                    channels={"incoming": pair.receiver},
                    deliveries={"outgoing": delivery},
                    client_channels=self.assignments,
                ),
            )
        except ValueError as error:
            self.fail(f"application reply capability missing: {error}")
        params = {
            "channel_id": "outgoing",
            "send_id": self.send_id,
            "received_channel_id": "incoming",
            "message_id": received["event_id"],
            "text": "Untrusted reply text $(not-executed)",
        }
        request = create_request(
            self.capability,
            request_id=_uuid("reply-rpc"),
            issued_at_ms=pair.now,
            method="messaging.reply",
            params=params,
        )
        response = self.invoke(hosted, request)
        self.assertTrue(response["ok"], response)
        reply = reverse_receiver.page(after=0, limit=1)[0]["message"]
        self.assertIsNone(
            reply["payload"]["reply"], "must not forge canonical direct reply"
        )
        self.assertEqual(
            reply["payload"]["intent"]["thread_id"],
            received["payload"]["intent"]["thread_id"],
        )
        self.assertEqual(
            reply["payload"]["body"]["response_context"],
            {
                "schema": "dm.messaging.application-response/v1",
                "message_id": received["event_id"],
                "message_hash": received["content_hash"],
                "sender_being_ref": received["being_ref"],
                "sender_embodiment_id": received["origin"]["embodiment_id"],
                "thread_id": received["payload"]["intent"]["thread_id"],
            },
        )
        self.assertNotIn(received["event_id"], reply["causal_parents"])
        self.assertIsNone(pair.local_ledger.event(received["event_id"]))
        self.assertEqual(self.invoke(hosted, request), response)
        self.assertEqual(len(calls), 2)
        self.assignments[self.capability.client_id] = frozenset({"outgoing"})
        self.assertFalse(self.invoke(hosted, request)["ok"])
        self.assertEqual(len(calls), 2)
        # Wrong source IDs are not enough authority, even when signed by the peer.
        self.assignments[self.capability.client_id] = frozenset(
            {"incoming", "outgoing"}
        )
        forged = create_request(
            self.capability,
            request_id=_uuid("forged-reply-rpc"),
            issued_at_ms=pair.now,
            method="messaging.reply",
            params={**params, "message_id": _uuid("not-received")},
        )
        self.assertFalse(self.invoke(hosted, forged)["ok"])
        self.assertEqual(len(calls), 2)

    def test_delivery_inspection_is_authenticated_read_only_and_current(self) -> None:
        from dataclasses import replace

        from daimon_matrix.local_api import create_capability, create_request

        pair, hosted, delivery, calls = self.setup_sender()
        self.capability = create_capability(
            _seed("native-send-client"),
            client_id=self.capability.client_id,
            methods=["messaging.send", "messaging.delivery"],
            not_before_ms=NOW,
            not_after_ms=NOW + 1_000_000,
        )
        try:
            hosted = replace(
                hosted, capabilities={self.capability.capability_id: self.capability}
            )
        except ValueError as error:
            self.fail(f"delivery inspection capability missing: {error}")
        self.assertTrue(self.invoke(hosted, self.request(pair))["ok"])
        request = create_request(
            self.capability,
            request_id=_uuid("inspect-rpc"),
            issued_at_ms=pair.now,
            method="messaging.delivery",
            params={"channel_id": "member", "send_id": self.send_id},
        )
        before = delivery.sender.outbox.path.read_bytes()
        result = self.invoke(hosted, request)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["transport_status"], "recipient-intake")
        self.assertEqual(len(calls), 2)
        self.assertEqual(before, delivery.sender.outbox.path.read_bytes())
        self.assignments[self.capability.client_id] = frozenset()
        self.assertFalse(self.invoke(hosted, request)["ok"])
        self.assertEqual(len(calls), 2)

    def test_cached_send_cannot_rebind_outbox_or_reauthor(self) -> None:
        from daimon_matrix.messaging_store import MessagingOutboxStore

        pair, hosted, delivery, calls = self.setup_sender()
        request = self.request(pair)
        self.assertTrue(self.invoke(hosted, request)["ok"])
        original = delivery.sender.outbox
        delivery.sender.outbox = MessagingOutboxStore(
            self.root / "sender/rebound.sqlite3"
        )
        events = delivery.sender.ledger.events()
        response = self.invoke(hosted, request)
        self.assertFalse(response["ok"], response)
        self.assertEqual(delivery.sender.ledger.events(), events)
        self.assertEqual(len(calls), 2)
        delivery.sender.outbox = original
        self.assertTrue(self.invoke(hosted, request)["ok"])

    def test_assignment_revoked_during_evidence_stops_message_stage(self) -> None:
        pair, hosted, delivery, calls = self.setup_sender()
        provider = delivery.providers[0]
        original = provider._round_trip

        def revoke(raw: bytes) -> bytes:
            result = original(raw)
            self.assignments[self.capability.client_id] = frozenset()
            return bytes(result)

        provider._round_trip = revoke
        response = self.invoke(hosted, self.request(pair))
        self.assertFalse(response["ok"], response)
        self.assertEqual([phase for phase, _ in calls], ["evidence"])
        self.assertEqual(pair.receiver.page(after=0, limit=1), [])

    def test_cached_send_rechecks_assignment_and_signed_grant(self) -> None:
        pair, hosted, delivery, calls = self.setup_sender()
        request = self.request(pair)
        self.assertTrue(self.invoke(hosted, request)["ok"])
        self.assignments[self.capability.client_id] = frozenset()
        response = self.invoke(hosted, request)
        self.assertFalse(response["ok"], "cached send bypassed channel revocation")
        self.assignments[self.capability.client_id] = frozenset({"member"})
        pair.sender_relationships.ingest(
            next(
                event
                for event in pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        pair.now = NOW + 17
        self.assertFalse(self.invoke(hosted, request)["ok"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(delivery.sender.ledger.events()), 3)

    def test_authenticated_send_reaches_independent_inbox_once(self) -> None:
        pair, hosted, delivery, calls = self.setup_sender()
        request = self.request(pair)
        response = self.invoke(hosted, request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["transport_status"], "recipient-intake")
        self.assertEqual(
            pair.receiver.page(after=0, limit=1)[0]["message"]["payload"]["body"][
                "text"
            ],
            TEXT,
        )
        self.assertEqual(self.invoke(hosted, request), response)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(delivery.sender.ledger.events()), 3)


class NativeMessagingTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dm132-native-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def make_sender(self, pair: Pair) -> Any:
        from daimon_matrix.messaging import MessagingSender
        from daimon_matrix.messaging_store import MessagingOutboxStore

        ledger = Ledger(
            self.root / "sender/local.sqlite3",
            authority=pair.sender.authority,
            local_origin=pair.sender.origin,
            clock=lambda: pair.now,
        )
        ledger.initialize()
        return MessagingSender(
            context=pair.sender_context,
            ledger=ledger,
            signer=pair.sender.signer,
            custody=pair.sender_custody,
            outbox=MessagingOutboxStore(self.root / "sender/outbox.sqlite3"),
            clock=lambda: pair.now,
        )

    def delivery_transports(
        self, pair: Pair, sender: Any, send_id: str
    ) -> tuple[Any, Any, list[tuple[str, bytes]]]:
        import sqlite3

        from daimon_matrix.routes import (
            AuthenticatedProvider,
            OpaqueInbox,
            TransportIngress,
        )

        calls: list[tuple[str, bytes]] = []
        providers = []
        for phase, callback in (
            ("evidence", pair.receiver.receive_evidence),
            ("message", pair.receiver.receive_message),
        ):

            def validate(raw: bytes, callback: Any = callback) -> None:
                callback(raw)

            ingress = TransportIngress(
                provider_ref="provider:" + phase,
                route_ref="route:" + phase,
                key_ref="fixture:transport",
                secret=bytes(range(32)),
                recipient_id=pair.policy.membership_ref,
                recipient_body_ref=pair.recipient.origin["body_ref"],
                recipient_embodiment_id=pair.recipient.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / "receiver" / (phase + "-opaque.sqlite3"),
                    clock=lambda: pair.now,
                ),
                clock=lambda: pair.now,
                intake_validator=validate,
            )

            def exchange(
                raw: bytes, phase: str = phase, ingress: Any = ingress
            ) -> bytes:
                # Separate connection proves the complete request and pending state
                # were committed, not merely inserted into an open transaction.
                with closing(sqlite3.connect(sender.outbox.path)) as database:
                    rows = database.execute(
                        "SELECT phase, request, transport_status "
                        "FROM messaging_transport_stages "
                        "WHERE owner=? AND send_id=? ORDER BY phase",
                        (pair.sender.state.being_ref, send_id),
                    ).fetchall()
                self.assertEqual(len(rows), 2)
                stages = {row[0]: row[1:] for row in rows}
                self.assertEqual(stages[phase], (raw, "pending"))
                if phase == "message":
                    self.assertEqual(stages["evidence"][1], "recipient-intake")
                calls.append((phase, raw))
                return bytes(ingress.handle(raw))

            providers.append(
                AuthenticatedProvider(
                    provider_ref="provider:" + phase,
                    route_ref="route:" + phase,
                    route_class="direct",
                    key_ref="fixture:transport",
                    secret=bytes(range(32)),
                    sender_principal=pair.sender.state.being_ref,
                    sender_body_ref=pair.sender.origin["body_ref"],
                    clock=lambda: pair.now,
                    round_trip=exchange,
                )
            )
        return providers[0], providers[1], calls

    def test_loaded_runtime_delivery_custody_uses_one_password_read(self) -> None:
        from dataclasses import replace

        from daimon_matrix.runtime import load_runtime
        from daimon_matrix.sealed import (
            open_event,
            recipient_descriptor,
            sender_descriptor,
        )
        from tests.test_dm022_ledger import seed
        from tests.test_dm024_runtime import PASSWORD, RuntimeFixture

        fixture = RuntimeFixture()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        state_root, bundle, _ = fixture.make_bundle(
            secrets={"peer.encryption.v1:local": seed("legion-encryption")}
        )
        bundle["peer_transport"] = {
            "enabled": True,
            "encryption_slot": "peer.encryption.v1:local",
            "exchange_filename": "peer-exchange.sqlite",
            "outbox_filename": "peer-outbox.sqlite",
            "listen_host": "127.0.0.1",
            "listen_port": 45193,
            "targets": [
                {
                    "embodiment_id": "embodiment:daimonmatrix",
                    "endpoint": "http://127.0.0.1:45194/dm-peer/v1",
                    "timeout_ms": 1000,
                }
            ],
        }
        (state_root / "runtime.json").write_bytes(canonical_bytes(bundle))
        original_custody = (state_root / "custody.json").read_bytes()
        reads = 0

        def one_shot() -> bytearray:
            nonlocal reads
            reads += 1
            self.assertEqual(reads, 1, "runtime password descriptor was reused")
            return bytearray(PASSWORD)

        runtime = load_runtime(state_root, "runtime.json", one_shot, clock=lambda: NOW)
        factory = runtime.create_delivery_custody
        context = runtime.peer_context
        assert context is not None
        event = fixture.append(fixture.ledger_a, "legion", "loaded-custody-roundtrip")
        target = context.local_target
        authorization = DisclosureAuthorization.synthetic(
            event=event,
            sender=sender_descriptor(event, context.authority, at_ms=NOW),
            recipients=[recipient_descriptor(target, at_ms=NOW)],
            evidence_hash="a" * 64,
            authorized_at_ms=NOW,
            expires_at_ms=NOW + 1000,
        )
        for _ in range(2):
            loaded = factory()
            envelope = seal_event(
                event,
                sender_authority=context.authority,
                recipients=[target],
                authorization=authorization,
                custody=loaded,
                issued_at_ms=NOW,
                expires_at_ms=NOW + 1000,
            )
            opened = open_event(
                envelope,
                sender_authority=context.authority,
                local_target=target,
                recipient_targets=[target],
                authorization=authorization,
                custody=loaded,
                at_ms=NOW + 1,
            )
            self.assertEqual(opened, event)
        self.assertEqual(reads, 1)
        self.assertEqual((state_root / "custody.json").read_bytes(), original_custody)
        self.assertEqual(json.loads((state_root / "runtime.json").read_bytes()), bundle)
        with self.assertRaisesRegex(ValueError, "messaging_custody_not_configured"):
            replace(runtime, peer_context=None).create_delivery_custody()

    def test_runtime_delivery_custody_preserves_domain_and_stable_rejection(
        self,
    ) -> None:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from daimon_matrix.peer_transport import SIGNATURE_DOMAIN as PEER_DOMAIN
        from daimon_matrix.peer_transport import KeystorePeerCustody
        from daimon_matrix.runtime import _RuntimeDeliveryCustody
        from daimon_matrix.sealed import SIGNATURE_DOMAIN, SealedDeliveryError

        identity = _identity("alpha")
        signing_id = identity.credential["body"]["signing_key"]["key_id"]
        encryption_id = identity.credential["body"]["encryption_key"]["key_id"]
        peer = KeystorePeerCustody(
            secrets={
                "runtime.signing.v1:test": _seed("alpha:signing"),
                "peer.encryption.v1:test": _seed("alpha:encryption"),
            },
            signing_slots={signing_id: "runtime.signing.v1:test"},
            encryption_slots={encryption_id: "peer.encryption.v1:test"},
        )
        loaded = _RuntimeDeliveryCustody(peer)
        unsigned = {"schema": "dm.sealed-delivery/v1", "probe": "domain separation"}
        signature = loaded.sign(signing_id, unsigned)
        public = Ed25519PrivateKey.from_private_bytes(
            _seed("alpha:signing")
        ).public_key()
        public.verify(signature, SIGNATURE_DOMAIN + canonical_bytes(unsigned))
        for wrong_domain in (b"", PEER_DOMAIN):
            with self.assertRaises(InvalidSignature):
                public.verify(signature, wrong_domain + canonical_bytes(unsigned))
        operations: tuple[Callable[[], bytes], ...] = (
            lambda: loaded.sign("unknown-key", unsigned),
            lambda: loaded.sign(signing_id, {"noncanonical": float("nan")}),
            lambda: loaded.unwrap("unknown-key", b"invalid", b"invalid"),
            lambda: loaded.unwrap(encryption_id, bytes(80), b"invalid"),
        )
        for index, operation in enumerate(operations):
            with (
                self.subTest(operation=index),
                self.assertRaisesRegex(
                    SealedDeliveryError, "^sealed_delivery_rejected$"
                ),
            ):
                operation()

    def test_production_messaging_http_listener_is_bounded_and_delivers(self) -> None:
        import http.client
        import socket
        import threading
        from unittest.mock import patch

        from daimon_matrix import daemon
        from daimon_matrix.messaging import MessagingDelivery
        from daimon_matrix.routes import (
            DirectHTTPProvider,
            OpaqueInbox,
            TransportIngress,
        )

        factory = getattr(daemon, "create_messaging_http_server", None)
        self.assertIsNotNone(factory, "production messaging HTTP listener is missing")
        assert factory is not None
        pair = Pair(self.root)
        sender = self.make_sender(pair)
        ingresses = {}
        for phase, callback in (
            ("evidence", pair.receiver.receive_evidence),
            ("message", pair.receiver.receive_message),
        ):

            def validate(raw: bytes, callback: Any = callback) -> None:
                callback(raw)

            ingresses[phase] = TransportIngress(
                provider_ref="provider:" + phase,
                route_ref="route:" + phase,
                key_ref="fixture:transport",
                secret=bytes(range(32)),
                recipient_id=pair.policy.membership_ref,
                recipient_body_ref=pair.recipient.origin["body_ref"],
                recipient_embodiment_id=pair.recipient.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / "receiver" / (phase + "-http.sqlite3"),
                    clock=lambda: pair.now,
                ),
                clock=lambda: pair.now,
                intake_validator=validate,
            )
        with factory(
            ("127.0.0.1", 0),
            evidence_ingress=ingresses["evidence"],
            message_ingress=ingresses["message"],
        ) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                dispatched: list[bytes] = []
                original = TransportIngress.handle

                def observe(ingress: TransportIngress, raw: bytes) -> bytes:
                    dispatched.append(raw)
                    return original(ingress, raw)

                path = "/dm-messaging/v1/evidence"
                bad_frames = [
                    (path, ["Content-Length: 2", "Content-Length: 2"], 400),
                    (path, ["Content-Length: 2", "Transfer-Encoding: chunked"], 400),
                    (path, ["Content-Length: -1"], 400),
                    (path, ["Content-Length: +2"], 400),
                    (path, ["Content-Length: 999999999"], 400),
                    (path, [], 400),
                    ("/unknown", ["Content-Length: 2"], 404),
                    (path + "?peer=other", ["Content-Length: 2"], 404),
                    (path, ["Content-Length: 2", "Content-Type: text/plain"], 400),
                ]
                with patch.object(TransportIngress, "handle", observe):
                    for target, extra, expected in bad_frames:
                        frame = (
                            f"POST {target} HTTP/1.1\r\nHost: localhost\r\n"
                            "Content-Type: application/daimon+jcs\r\n"
                            + "\r\n".join(extra)
                            + "\r\n\r\n{}"
                        ).encode()
                        with (
                            self.subTest(headers=extra, path=target),
                            socket.create_connection(
                                server.server_address, timeout=2
                            ) as connection,
                        ):
                            connection.sendall(frame)
                            with http.client.HTTPResponse(connection) as response:
                                response.begin()
                                self.assertEqual(response.status, expected)
                                self.assertEqual(response.read(), b"")
                                self.assertEqual(
                                    response.getheader("Connection"), "close"
                                )
                    self.assertEqual(dispatched, [])
                # Correct HTTP framing never substitutes for transport authentication.
                with closing(
                    http.client.HTTPConnection(
                        "127.0.0.1", server.server_port, timeout=2
                    )
                ) as http_connection:
                    http_connection.request(
                        "POST",
                        path,
                        body=b"{}",
                        headers={"Content-Type": "application/daimon+jcs"},
                    )
                    with http_connection.getresponse() as response:
                        self.assertEqual(response.status, 400)
                        self.assertEqual(response.read(), b"")
                self.assertEqual(pair.receiver.page(after=0, limit=10), [])
                providers = [
                    DirectHTTPProvider(
                        endpoint=f"http://127.0.0.1:{server.server_port}/dm-messaging/v1/{phase}",
                        provider_ref="provider:" + phase,
                        route_ref="route:" + phase,
                        route_class="direct",
                        key_ref="fixture:transport",
                        secret=bytes(range(32)),
                        sender_principal=pair.sender.state.being_ref,
                        sender_body_ref=pair.sender.origin["body_ref"],
                        clock=lambda: pair.now,
                    )
                    for phase in ("evidence", "message")
                ]
                delivery = MessagingDelivery(
                    sender=sender,
                    evidence_provider=providers[0],
                    message_provider=providers[1],
                    config_digest="b" * 64,
                )
                request: _SendRequest = dict(
                    client_id="owner-ui",
                    send_id=_uuid("production-http"),
                    thread_id=_uuid("thread"),
                    text=TEXT,
                )
                result = delivery.send(**request)
                self.assertEqual(result["transport_status"], "recipient-intake")
                self.assertEqual(delivery.send(**request), result)
                self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)
                self.assertEqual(len(sender.ledger.events()), 3)
                self.assertEqual(pair.local_ledger.events(), [])
            finally:
                server.shutdown()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())

    def test_delivery_stages_are_durable_before_independent_intake(self) -> None:
        import sqlite3

        from daimon_matrix import messaging
        from daimon_matrix.canonical import unb64url

        delivery_type = getattr(messaging, "MessagingDelivery", None)
        self.assertIsNotNone(delivery_type, "durable delivery facade is missing")
        assert delivery_type is not None
        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("delivery-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        delivery = delivery_type(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        result = delivery.send(**request)
        self.assertEqual(result["phase"], "message")
        self.assertEqual(result["transport_status"], "recipient-intake")
        self.assertFalse(result["retryable"])
        self.assertFalse(result["ambiguous"])
        self.assertNotIn("receipt", result)
        self.assertEqual([phase for phase, _ in calls], ["evidence", "message"])
        submissions = [json.loads(raw)["submission"] for _, raw in calls]
        self.assertNotEqual(submissions[0]["attempt_id"], submissions[1]["attempt_id"])
        self.assertEqual(
            [s["leg_id"] for s in submissions],
            ["application-stage:evidence", "application-stage:message"],
        )
        pair_bytes = tuple(unb64url(s["envelope"]) for s in submissions)
        self.assertEqual(sender.prepare(**request), pair_bytes)
        self.assertTrue(all(TEXT.encode() not in raw for _, raw in calls))
        events = sender.ledger.events()
        self.assertEqual(len(events), 3)
        page = pair.receiver.page(after=0, limit=10)
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0]["message"], events[0])
        self.assertEqual(page[0]["evidence"], events[2])
        self.assertEqual(pair.local_ledger.events(), [])
        with closing(sqlite3.connect(sender.outbox.path)) as database:
            rows = database.execute(
                "SELECT transport_status FROM messaging_transport_stages ORDER BY phase"
            ).fetchall()
        self.assertEqual(rows, [("recipient-intake",), ("recipient-intake",)])

        # Real receiver policy refusal must not release the second stage.
        pair.receiver_relationships.ingest(
            next(
                event
                for event in pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        pair.now = NOW + 17
        request["send_id"] = _uuid("refused-delivery")
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        result = delivery_type(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        ).send(**request)
        self.assertEqual(result["phase"], "evidence")
        self.assertEqual(result["transport_status"], "refused")
        self.assertFalse(result["retryable"])
        self.assertEqual([phase for phase, _ in calls], ["evidence"])

    def test_delivery_restart_retries_exact_request_after_real_admission(self) -> None:
        import sqlite3

        from daimon_matrix.messaging import MessagingDelivery
        from daimon_matrix.routes import RouteError

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("lost-delivery"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        exchange = message._round_trip

        def lose_result(raw: bytes) -> bytes:
            exchange(raw)  # Actual recipient admission, not a fabricated success.
            raise ConnectionError("response lost after admission")

        message._round_trip = lose_result
        delivery = MessagingDelivery(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        try:
            pending = delivery.send(**request)
        except RouteError as exception:
            self.fail(f"lost result must return durable pending progress: {exception}")
        self.assertEqual(pending["phase"], "message")
        self.assertEqual(pending["transport_status"], "pending")
        self.assertTrue(pending["ambiguous"])
        self.assertTrue(pending["retryable"])
        page = pair.receiver.page(after=0, limit=10)
        self.assertEqual(len(page), 1)
        with closing(sqlite3.connect(sender.outbox.path)) as database:
            rows = database.execute(
                "SELECT phase, request, transport_status, result_sha256 "
                "FROM messaging_transport_stages ORDER BY phase"
            ).fetchall()
        self.assertEqual(rows[0][2], "recipient-intake")
        self.assertIsNotNone(rows[0][3])
        self.assertEqual(rows[1][2:], ("pending", None))
        original_pair = sender.prepare(**request)
        original_events = sender.ledger.events()
        pair.now += 1
        restarted = self.make_sender(pair)
        evidence, message, retried = self.delivery_transports(
            pair, restarted, request["send_id"]
        )
        delivery = MessagingDelivery(
            sender=restarted,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        accepted = delivery.send(**request)
        self.assertEqual(accepted["transport_status"], "recipient-intake")
        self.assertEqual(retried, [calls[-1]])
        self.assertEqual(retried[0][1], rows[1][1])
        self.assertEqual(pair.receiver.page(after=0, limit=10), page)
        self.assertEqual(restarted.prepare(**request), original_pair)
        self.assertEqual(restarted.ledger.events(), original_events)
        self.assertEqual(pair.local_ledger.events(), [])
        self.assertEqual(delivery.send(**request), accepted)
        self.assertEqual(len(retried), 1)

        # Admission without an authenticated response is not evidence acceptance.
        request["send_id"] = _uuid("unauthenticated-evidence-result")
        evidence, message, calls = self.delivery_transports(
            pair, restarted, request["send_id"]
        )
        exchange = evidence._round_trip

        def damage_response(raw: bytes) -> bytes:
            response = json.loads(exchange(raw))
            response["auth"]["value"] = "A" * 43
            return canonical_bytes(response)

        evidence._round_trip = damage_response
        pending = MessagingDelivery(
            sender=restarted,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        ).send(**request)
        self.assertEqual(pending["phase"], "evidence")
        self.assertEqual(pending["transport_status"], "pending")
        self.assertTrue(pending["ambiguous"])
        self.assertEqual([phase for phase, _ in calls], ["evidence"])
        self.assertEqual(pair.receiver.page(after=0, limit=10), page)

    def test_delivery_rejects_unproven_cached_success_before_io(self) -> None:
        import sqlite3
        from unittest.mock import patch

        from daimon_matrix.messaging import MessagingDelivery

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("false-success"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        delivery = MessagingDelivery(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        # Neither peer has admitted anything: interrupt the first byte-I/O seam.
        with patch.object(evidence, "_round_trip", side_effect=ConnectionError):
            self.assertEqual(delivery.send(**request)["transport_status"], "pending")
        self.assertEqual(pair.receiver.page(after=0, limit=10), [])
        with closing(sqlite3.connect(sender.outbox.path)) as database, database:
            database.execute(
                "UPDATE messaging_transport_stages "
                "SET transport_status='recipient-intake', "
                "result_sha256=?",
                ("0" * 64,),
            )
        with self.assertRaises(ValueError):
            delivery.send(**request)
        self.assertEqual(calls, [])
        self.assertEqual(pair.receiver.page(after=0, limit=10), [])

    def test_delivery_retains_pending_after_truncated_http_response(self) -> None:
        import http.client

        from daimon_matrix.messaging import MessagingDelivery

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("truncated-response"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        exchange = message._round_trip

        def truncate(raw: bytes) -> bytes:
            response = exchange(raw)
            raise http.client.IncompleteRead(response[:1], len(response) - 1)

        message._round_trip = truncate
        delivery = MessagingDelivery(
            sender=sender,
            evidence_provider=evidence,
            message_provider=message,
            config_digest="a" * 64,
        )
        result = delivery.send(**request)
        self.assertEqual(result["transport_status"], "pending")
        self.assertTrue(result["ambiguous"])
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)
        original = calls[-1]
        message._round_trip = exchange
        self.assertEqual(
            delivery.send(**request)["transport_status"], "recipient-intake"
        )
        self.assertEqual(calls[-1], original)
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)

    def test_delivery_conflicts_and_current_authority_block_all_io(self) -> None:
        import sqlite3
        from dataclasses import replace

        from daimon_matrix.messaging import MessagingDelivery

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("gated-delivery"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        evidence, message, calls = self.delivery_transports(
            pair, sender, request["send_id"]
        )
        options = dict(
            sender=sender, evidence_provider=evidence, message_provider=message
        )
        for invalid in ("", "a" * 63, "g" * 64, "A" * 64):
            with (
                self.subTest(digest=invalid),
                self.assertRaisesRegex(ValueError, "config_digest"),
            ):
                MessagingDelivery(**options, config_digest=invalid)
        delivery = MessagingDelivery(**options, config_digest="a" * 64)
        original_io = evidence._round_trip

        def lose_evidence_result(raw: bytes) -> bytes:
            original_io(raw)
            raise ConnectionError("lost evidence result")

        evidence._round_trip = lose_evidence_result
        self.assertEqual(delivery.send(**request)["transport_status"], "pending")
        original_pair = sender.prepare(**request)
        original_events = sender.ledger.events()
        for cached in (False, True):
            before_calls = list(calls)
            before_database = sender.outbox.path.read_bytes()
            with self.subTest(cached=cached):
                for changed in (
                    {"client_id": "other-client"},
                    {"text": "different text"},
                    {"thread_id": _uuid("other-thread")},
                ):
                    with self.assertRaisesRegex(ValueError, "messaging_send_conflict"):
                        delivery.send(**cast(_SendRequest, {**request, **changed}))
                with self.assertRaisesRegex(ValueError, "messaging_transport_conflict"):
                    MessagingDelivery(**options, config_digest="b" * 64).send(**request)
                # Even a misconfigured owner reusing a digest cannot rebind the
                # second provider's visible route/key/body fields before evidence I/O.
                for field, alternative in (
                    ("_provider_ref", "provider:other"),
                    ("_route_ref", "route:other"),
                    ("_route_class", "hub"),
                    ("_key_ref", "fixture:other"),
                    ("_secret", bytes(reversed(range(32)))),
                    ("_sender_principal", "being:other"),
                    ("_sender_body_ref", "body:other"),
                ):
                    original = getattr(message, field)
                    setattr(message, field, alternative)
                    try:
                        with self.subTest(field=field), self.assertRaises(ValueError):
                            delivery.send(**request)
                    finally:
                        setattr(message, field, original)
                sender.context.policy = replace(pair.policy, max_ttl_ms=20_000)
                try:
                    with self.assertRaises(ValueError):
                        delivery.send(**request)
                finally:
                    sender.context.policy = pair.policy
                pair.now = json.loads(original_pair[0])["expires_at_ms"]
                with self.assertRaisesRegex(
                    ValueError, "messaging_authorization_expired"
                ):
                    delivery.send(**request)
                pair.now = NOW + 11
                self.assertEqual(calls, before_calls)
                self.assertEqual(sender.outbox.path.read_bytes(), before_database)
                self.assertEqual(sender.ledger.events(), original_events)
            if not cached:
                # Also reject corruption or freshly reauthenticated replacement of
                # persisted requests; never silently accept regenerated timestamps.
                with closing(sqlite3.connect(sender.outbox.path)) as database:
                    raw = database.execute(
                        "SELECT request FROM messaging_transport_stages "
                        "WHERE phase='message'"
                    ).fetchone()[0]
                regenerated = message.prepare_submission(json.loads(raw)["submission"])
                self.assertNotEqual(raw, regenerated)
                for changed_raw in (raw + b"\n", regenerated):
                    with (
                        closing(sqlite3.connect(sender.outbox.path)) as database,
                        database,
                    ):
                        database.execute(
                            "UPDATE messaging_transport_stages SET request=? "
                            "WHERE phase='message'",
                            (changed_raw,),
                        )
                    with self.assertRaisesRegex(
                        ValueError, "messaging_transport_conflict"
                    ):
                        delivery.send(**request)
                    self.assertEqual(calls, before_calls)
                    with (
                        closing(sqlite3.connect(sender.outbox.path)) as database,
                        database,
                    ):
                        database.execute(
                            "UPDATE messaging_transport_stages SET request=? "
                            "WHERE phase='message'",
                            (raw,),
                        )
                evidence._round_trip = original_io
                self.assertEqual(
                    delivery.send(**request)["transport_status"], "recipient-intake"
                )
        self.assertEqual(sender.prepare(**request), original_pair)

        # A long evidence round trip cannot carry an expired authorization onward.
        later: _SendRequest = {**request, "send_id": _uuid("expires-between-stages")}
        evidence, message, later_calls = self.delivery_transports(
            pair, sender, later["send_id"]
        )
        original_io = evidence._round_trip

        def expire_after_evidence(raw: bytes) -> bytes:
            response = original_io(raw)
            pair.now = json.loads(raw)["expires_at_ms"]
            return bytes(response)

        evidence._round_trip = expire_after_evidence
        with self.assertRaisesRegex(ValueError, "messaging_authorization_expired"):
            MessagingDelivery(
                sender=sender,
                evidence_provider=evidence,
                message_provider=message,
                config_digest="a" * 64,
            ).send(**later)
        self.assertEqual([phase for phase, _ in later_calls], ["evidence"])

        pair.now = NOW + 17
        pair.sender_relationships.ingest(
            next(
                event
                for event in pair.history
                if event["kind"] == "matrix/relationship-grant-revocation"
            )
        )
        before_calls = list(calls)
        before_database = sender.outbox.path.read_bytes()
        for original_request in (request, later):
            with self.assertRaises(ValueError):
                delivery.send(**original_request)
        self.assertEqual(calls, before_calls)
        self.assertEqual(sender.outbox.path.read_bytes(), before_database)
        self.assertEqual(pair.local_ledger.events(), [])

    def test_prepared_http_retry_preserves_request_after_lost_response(self) -> None:
        import hashlib
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from daimon_matrix.canonical import b64url
        from daimon_matrix.routes import (
            ROUTE_SUBMISSION_SCHEMA,
            DirectHTTPProvider,
            OpaqueInbox,
            RouteAmbiguous,
            TransportIngress,
        )

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        envelopes = sender.prepare(
            client_id="owner-ui",
            send_id=_uuid("http-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        secret = bytes(
            range(32)
        )  # Disposable fixture transport key, not identity custody.
        requests: dict[str, list[bytes]] = {"evidence": [], "message": []}
        drop_response = {"message": True}
        ingresses = {}
        for phase, validate in (
            ("evidence", pair.receiver.receive_evidence),
            ("message", pair.receiver.receive_message),
        ):

            def validator(raw: bytes, callback: Any = validate) -> None:
                callback(raw)

            ingresses[phase] = TransportIngress(
                provider_ref="provider:" + phase,
                route_ref="route:" + phase,
                key_ref="fixture:transport",
                secret=secret,
                recipient_id=pair.policy.membership_ref,
                recipient_body_ref=pair.recipient.origin["body_ref"],
                recipient_embodiment_id=pair.recipient.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / "receiver" / (phase + "-opaque.sqlite3"),
                    clock=lambda: pair.now,
                ),
                clock=lambda: pair.now,
                intake_validator=validator,
            )

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                phase = self.path.removeprefix("/")
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                requests[phase].append(raw)
                response = ingresses[phase].handle(raw)
                if drop_response.pop(phase, False):
                    self.close_connection = True
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        with HTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:

                def provider(phase: str) -> DirectHTTPProvider:
                    return DirectHTTPProvider(
                        endpoint=f"http://127.0.0.1:{server.server_port}/{phase}",
                        provider_ref="provider:" + phase,
                        route_ref="route:" + phase,
                        route_class="direct",
                        key_ref="fixture:transport",
                        secret=secret,
                        sender_principal=pair.sender.state.being_ref,
                        sender_body_ref=pair.sender.origin["body_ref"],
                        clock=lambda: pair.now,
                    )

                for phase, envelope in zip(
                    ("evidence", "message"), envelopes, strict=True
                ):
                    value = json.loads(envelope)
                    submission = {
                        "schema": ROUTE_SUBMISSION_SCHEMA,
                        "attempt_id": _uuid("http-" + phase),
                        "leg_id": "application-stage:" + phase,
                        "message_id": value["event_id"],
                        "recipient_id": pair.policy.membership_ref,
                        "delivery_id": value["delivery_id"],
                        "envelope": b64url(envelope),
                        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
                        "deadline_ms": value["expires_at_ms"],
                    }
                    transport = provider(phase)
                    prepared = transport.prepare_submission(submission)
                    self.assertEqual(
                        requests[phase], []
                    )  # Preparation performs no I/O.
                    path = self.root / "sender" / (phase + "-prepared.json")
                    path.touch(mode=0o600)
                    path.write_bytes(prepared)
                    if phase == "message":
                        with self.assertRaises(RouteAmbiguous):
                            transport.send_prepared(path.read_bytes())
                        pair.now += 1
                    result = provider(phase).send_prepared(path.read_bytes())
                    self.assertEqual(result["outcome"], "recipient-intake")
                    self.assertTrue(all(raw == prepared for raw in requests[phase]))
                    self.assertNotIn(TEXT.encode(), prepared)
                self.assertEqual(len(requests["message"]), 2)
                self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)
                self.assertEqual(len(sender.ledger.events()), 3)
                self.assertEqual(pair.local_ledger.events(), [])
            finally:
                server.shutdown()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())

    def test_prepared_transport_rejects_invalid_or_rebound_bytes_before_io(
        self,
    ) -> None:
        import hashlib

        from daimon_matrix.canonical import b64url
        from daimon_matrix.routes import (
            ROUTE_SUBMISSION_SCHEMA,
            AuthenticatedProvider,
            RouteError,
        )

        pair = Pair(self.root)
        envelope = self.make_sender(pair).prepare(
            client_id="owner-ui",
            send_id=_uuid("transport-negative"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )[0]
        metadata = json.loads(envelope)
        calls: list[bytes] = []

        def forbidden_io(raw: bytes) -> bytes:
            calls.append(raw)
            raise ConnectionError("negative control reached I/O")

        options: dict[str, Any] = dict(
            provider_ref="provider:fixed",
            route_ref="route:fixed",
            route_class="direct",
            key_ref="fixture:transport",
            secret=bytes(range(32)),
            sender_principal=pair.sender.state.being_ref,
            sender_body_ref=pair.sender.origin["body_ref"],
            round_trip=forbidden_io,
            clock=lambda: pair.now,
        )
        provider = AuthenticatedProvider(**options)
        submission = dict(
            schema=ROUTE_SUBMISSION_SCHEMA,
            attempt_id=_uuid("transport-negative-attempt"),
            leg_id="application-stage:evidence",
            message_id=metadata["event_id"],
            recipient_id=pair.policy.membership_ref,
            delivery_id=metadata["delivery_id"],
            envelope=b64url(envelope),
            envelope_sha256=hashlib.sha256(envelope).hexdigest(),
            deadline_ms=metadata["expires_at_ms"],
        )
        prepared = provider.prepare_submission(submission)
        value = json.loads(prepared)
        bad_auth = copy.deepcopy(value)
        bad_auth["auth"]["value"] = "A" * 43
        malformed = [
            b"{}",
            b"[]",
            prepared + b"\n",
            canonical_bytes(bad_auth),
            canonical_bytes({**value, "extra": True}),
            canonical_bytes({k: v for k, v in value.items() if k != "auth"}),
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:20]), self.assertRaises(RouteError):
                provider.send_prepared(raw)
            self.assertEqual(calls, [])
        for field, alternative in (
            ("provider_ref", "provider:other"),
            ("route_ref", "route:other"),
            ("key_ref", "fixture:other"),
            ("secret", bytes(reversed(range(32)))),
            ("sender_principal", "being:other"),
            ("sender_body_ref", "body:other"),
        ):
            other = AuthenticatedProvider(**{**options, field: alternative})
            with self.subTest(field=field), self.assertRaises(RouteError):
                other.send_prepared(prepared)
            self.assertEqual(calls, [])
        for at in (metadata["expires_at_ms"], NOW - 60_000):
            pair.now = at
            with self.subTest(at=at), self.assertRaises(RouteError):
                provider.send_prepared(prepared)
            self.assertEqual(calls, [])
        pair.now = NOW + 10
        with self.assertRaises(RouteError):
            provider.send_prepared(prepared)
        self.assertEqual(
            calls, [prepared]
        )  # Valid control alone reaches the I/O boundary.

    def test_sender_recovers_interrupted_authoring_without_duplicate_events(
        self,
    ) -> None:
        from unittest.mock import patch

        from daimon_matrix.weave import EventSigner

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("interrupted-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        original = EventSigner.signature
        calls = 0

        def interrupted(signer: EventSigner, content_hash: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic signing device interrupted")
            return dict(original(signer, content_hash))

        with (
            patch.object(EventSigner, "signature", new=interrupted),
            self.assertRaises(OSError),
        ):
            sender.prepare(**request)
        partial = sender.ledger.events()
        self.assertEqual(len(partial), 1)
        self.assertIsNone(
            sender.outbox._prepared(pair.sender.state.being_ref, request["send_id"])
        )
        pair.now += 1
        restarted = self.make_sender(pair)
        evidence, message = restarted.prepare(**request)
        recovered = restarted.ledger.events()
        self.assertEqual(len(recovered), 3)
        self.assertEqual(recovered[0], partial[0])
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(
            pair.receiver.page(after=0, limit=10)[0]["message"], partial[0]
        )
        self.assertEqual(restarted.prepare(**request), (evidence, message))
        self.assertEqual(pair.local_ledger.events(), [])

    def test_sender_prepares_real_local_events_for_independent_receiver(self) -> None:
        pair = Pair(self.root)
        sender = self.make_sender(pair)
        evidence, message = sender.prepare(
            client_id="owner-ui",
            send_id=_uuid("send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        events = sender.ledger.events()
        self.assertEqual(
            [event["subject"] for event in events],
            ["communication", "communication-resolution", "communication-evidence"],
        )
        self.assertEqual([event["sequence"] for event in events], [1, 2, 3])
        self.assertTrue(
            all(event["being_ref"] == pair.sender.state.being_ref for event in events)
        )
        self.assertTrue(all(TEXT.encode() not in raw for raw in (evidence, message)))
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        page = pair.receiver.page(after=0, limit=10)
        self.assertEqual(page[0]["message"]["payload"]["body"]["text"], TEXT)
        self.assertIsNone(page[0]["message"]["payload"]["reply"])
        self.assertEqual(page[0]["message"], events[0])
        self.assertEqual(page[0]["evidence"], events[2])
        self.assertEqual(pair.local_ledger.events(), [])

    def test_sender_retry_restart_preserves_envelopes_and_checks_fresh_authority(
        self,
    ) -> None:
        import sqlite3

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("retry-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        first = sender.prepare(**request)
        events = sender.ledger.events()
        pair.now += 1
        self.assertEqual(sender.prepare(**request), first)
        restarted = self.make_sender(pair)
        self.assertEqual(restarted.prepare(**request), first)
        self.assertEqual(restarted.ledger.events(), events)
        with closing(sqlite3.connect(restarted.outbox.path)) as database:
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox"
            ).fetchone()
        self.assertEqual(tuple(row), first)
        before = restarted.outbox.path.read_bytes()
        pair.now = json.loads(first[0])["expires_at_ms"]
        with self.assertRaisesRegex(ValueError, "messaging_authorization_expired"):
            restarted.prepare(**request)
        self.assertEqual(restarted.outbox.path.read_bytes(), before)
        self.assertEqual(restarted.ledger.events(), events)
        revocation = next(
            event
            for event in pair.history
            if event["kind"] == "matrix/relationship-grant-revocation"
        )
        pair.sender_relationships.ingest(revocation)
        pair.now = NOW + 17
        with self.assertRaises(ValueError):
            restarted.prepare(**request)
        self.assertEqual(restarted.outbox.path.read_bytes(), before)
        self.assertEqual(restarted.ledger.events(), events)

    def test_sender_rejects_changed_request_policy_or_owner_without_mutation(
        self,
    ) -> None:
        from dataclasses import replace

        pair = Pair(self.root)
        sender = self.make_sender(pair)
        request: _SendRequest = dict(
            client_id="owner-ui",
            send_id=_uuid("bound-send"),
            thread_id=_uuid("thread"),
            text=TEXT,
        )
        first = sender.prepare(**request)
        before = sender.outbox.path.read_bytes()
        events = sender.ledger.events()
        for changed in (
            {"text": "changed"},
            {"thread_id": _uuid("other-thread")},
            {"client_id": "other-client"},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaisesRegex(ValueError, "messaging_send_conflict"),
            ):
                sender.prepare(**{**request, **changed})
        sender.context.policy = replace(pair.policy, max_ttl_ms=20_000)
        with self.assertRaisesRegex(ValueError, "messaging_send_conflict"):
            sender.prepare(**request)
        sender.context.policy = pair.policy
        for field, value in (
            ("local_being_ref", pair.sender.state.being_ref),
            ("local_credential_id", pair.sender.credential["artifact_id"]),
        ):
            original = getattr(sender.context, field)
            setattr(sender.context, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                sender.prepare(**request)
            setattr(sender.context, field, original)
        self.assertEqual(sender.outbox.path.read_bytes(), before)
        self.assertEqual(sender.ledger.events(), events)
        self.assertEqual(sender.prepare(**request), first)
        sender.ledger = pair.local_ledger
        for send_id in (request["send_id"], _uuid("wrong-owner")):
            with self.assertRaisesRegex(ValueError, "messaging_sender_binding"):
                sender.prepare(**{**request, "send_id": send_id})
        self.assertEqual(pair.local_ledger.events(), [])
        sender = self.make_sender(pair)
        for field in ("embodiment_id", "incarnation_id", "body_ref", "principal_id"):
            original = sender.ledger.local_origin[field]
            sender.ledger.local_origin[field] = "unconfigured"
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "messaging_sender_binding"),
            ):
                sender.prepare(**request)
            sender.ledger.local_origin[field] = original
        sender.signer = pair.recipient.signer
        with self.assertRaisesRegex(ValueError, "messaging_sender_binding"):
            sender.prepare(**request)
        sender.signer = pair.sender.signer
        invalid_requests: list[dict[str, Any]] = [
            {"text": 123},
            {"send_id": "not-a-uuid"},
            {"client_id": ""},
            {"thread_id": "not-a-uuid"},
        ]
        for invalid_request in invalid_requests:
            with self.subTest(changed=invalid_request), self.assertRaises(ValueError):
                sender.prepare(**{**request, **invalid_request})
        self.assertEqual(sender.outbox.path.read_bytes(), before)
        self.assertEqual(sender.ledger.events(), events)

    def test_independent_encrypted_evidence_materializes_actual_foreign_body(
        self,
    ) -> None:
        pair = Pair(self.root)
        evidence_wire, message_wire, message, evidence = pair.wire()
        assert pair.local_ledger.authority is pair.recipient.authority
        before = (self.root / "receiver/local.sqlite3").read_bytes()
        for raw in (evidence_wire, message_wire):
            assert TEXT.encode() not in raw
            assert canonical_bytes(evidence["payload"]["resolution_event"]) not in raw
        assert TEXT.encode() not in canonical_bytes(evidence)
        pair.receiver.receive_evidence(evidence_wire)
        result = pair.receiver.receive_message(message_wire)
        page = pair.receiver.page(after=0, limit=10)
        assert len(page) == 1
        assert page[0]["inbox_sequence"] == result["inbox_sequence"]
        assert page[0]["message"] == message
        assert page[0]["evidence"] == evidence
        assert page[0]["message"]["payload"]["body"]["text"] == TEXT
        assert (self.root / "receiver/local.sqlite3").read_bytes() == before

    def test_duplicate_reseal_and_restart_keep_one_immutable_item(self) -> None:
        from daimon_matrix.messaging import MessagingChannel
        from daimon_matrix.messaging_store import MessagingInboxStore

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        first = pair.receiver.receive_message(message)
        pair.receiver.receive_evidence(evidence)
        assert pair.receiver.receive_message(message) == first
        resealed_evidence, resealed_message, _, _ = pair.wire()
        assert resealed_evidence != evidence and resealed_message != message
        pair.receiver.receive_evidence(resealed_evidence)
        assert pair.receiver.receive_message(resealed_message) == first
        expected = pair.receiver.page(after=0, limit=10)
        restarted = MessagingChannel(
            **pair.channel_options,
            relationships=pair.receiver_relationships,
            inbox=MessagingInboxStore(pair.store_path),
            clock=lambda: NOW + 25_000,
        )
        # Delivery envelopes expired; historical access does not unwrap again.
        assert restarted.page(after=0, limit=10) == expected
        assert len(expected) == 1

    def test_manual_pages_are_bounded_ordered_and_do_not_consume(self) -> None:
        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        for sequence in (200, 100):
            evidence, message, _, _ = pair.wire(sequence)
            pair.receiver.receive_evidence(evidence)
            pair.receiver.receive_message(message)
        first = pair.receiver.page(after=0, limit=1)
        assert pair.receiver.page(after=0, limit=1) == first
        second = pair.receiver.page(after=first[0]["inbox_sequence"], limit=1)
        assert first[0]["message"]["sequence"] == 200
        assert second[0]["message"]["sequence"] == 100
        assert pair.receiver.page(after=second[0]["inbox_sequence"], limit=1) == []
        for after, limit in ((-1, 1), (True, 1), (0, 0), (0, -1), (0, 101), (0, True)):
            with (
                self.subTest(after=after, limit=limit),
                self.assertRaises(MessagingInboxError),
            ):
                pair.receiver.page(after=after, limit=limit)

    def test_foreign_origin_position_conflict_does_not_mutate_inbox(self) -> None:
        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire(100)
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        before = pair.receiver.page(after=0, limit=10)
        # The second resolution occupies the first evidence event's origin position.
        conflicting, _, _, _ = pair.wire(101)
        with self.assertRaisesRegex(MessagingInboxError, "conflict"):
            pair.receiver.receive_evidence(conflicting)
        assert pair.receiver.page(after=0, limit=10) == before

    def test_reusing_delivery_identity_for_new_ciphertext_fails_closed(self) -> None:
        import uuid
        from unittest.mock import patch

        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        delivery_ids = [
            uuid.UUID(json.loads(raw)["delivery_id"]) for raw in (evidence, message)
        ]
        # Control UUID generation only; both envelopes are genuinely signed.
        with patch("daimon_matrix.sealed.uuid.uuid4", side_effect=delivery_ids):
            conflicting_evidence, conflicting_message, _, _ = pair.wire()
        assert evidence != conflicting_evidence and message != conflicting_message
        with self.assertRaisesRegex(MessagingInboxError, "delivery_conflict"):
            pair.receiver.receive_evidence(conflicting_evidence)
        with self.assertRaisesRegex(MessagingInboxError, "delivery_conflict"):
            pair.receiver.receive_message(conflicting_message)

    def test_retained_bytes_are_checked_on_read_and_after_restart(self) -> None:
        import sqlite3
        from unittest.mock import patch

        from daimon_matrix.messaging_store import (
            MessagingInboxError,
            MessagingInboxStore,
        )

        pair = Pair(self.root)
        evidence_wire, message_wire, message, evidence = pair.wire()
        pair.receiver.receive_evidence(evidence_wire)
        pair.receiver.receive_message(message_wire)
        changed = copy.deepcopy(message)
        changed["payload"]["body"]["text"] = "unsigned substituted body"
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute("UPDATE inbox SET message=?", (canonical_bytes(changed),))
        pair.receiver.inbox = MessagingInboxStore(pair.store_path)
        with self.assertRaises(MessagingInboxError):
            pair.receiver.page(after=0, limit=10)
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute("UPDATE inbox SET message=?", (canonical_bytes(message),))
            changed_evidence = copy.deepcopy(evidence)
            changed_evidence["signature"]["value"] = "A" * 86
            database.execute(
                "UPDATE evidence SET event=?", (canonical_bytes(changed_evidence),)
            )
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(MessagingInboxError):
                pair.receiver.receive_message(message_wire)
            unwrap.assert_not_called()

    def test_missing_evidence_is_retryable_without_decryption(self) -> None:
        from unittest.mock import patch

        from daimon_matrix.communication import CommunicationError

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(CommunicationError) as caught:
                pair.receiver.receive_message(message)
            self.assertTrue(caught.exception.retryable)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)

    def test_signature_policy_and_expiry_fail_before_unwrap(self) -> None:
        from dataclasses import replace
        from unittest.mock import patch

        pair = Pair(self.root)
        evidence, _, _, _ = pair.wire()
        mutated = json.loads(evidence)
        mutated["signature"]["value"] = "A" * 86
        before = pair.store_path.read_bytes()
        policies = [
            pair.policy,
            replace(pair.policy, resource_ref="unapproved-resource"),
            replace(pair.policy, operation="write"),
            replace(pair.policy, classification="private"),
            replace(
                pair.policy, peer_credential_id=pair.recipient.credential["artifact_id"]
            ),
        ]
        for index, policy in enumerate(policies):
            with self.subTest(index=index):
                pair.receiver.policy = policy
                raw = canonical_bytes(mutated) if index == 0 else evidence
                with patch.object(
                    pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
                ) as unwrap:
                    with self.assertRaises(ValueError):
                        pair.receiver.receive_evidence(raw)
                    unwrap.assert_not_called()
                self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.policy = pair.policy
        pair.now = NOW + 20_001
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.now = NOW + 10
        pair.receiver.receive_evidence(evidence)

    def test_grant_requires_acceptance_and_current_nonrevocation(self) -> None:
        from unittest.mock import patch

        pair = Pair(self.root)
        evidence, message, _, _ = pair.wire()
        unaccepted = RelationshipStore(
            self.root / "unaccepted.sqlite3",
            authority_resolver=lambda being_ref: pair.public[being_ref],
        )
        for event in pair.history:
            if (
                event["occurred_at_ms"] <= NOW + 7
                and event["kind"] != "matrix/relationship-grant-acceptance"
            ):
                unaccepted.ingest(event)
        pair.receiver.relationships = unaccepted
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)
        pair.receiver.relationships = pair.receiver_relationships
        pair.receiver.receive_evidence(evidence)
        pair.receiver.receive_message(message)
        self.assertEqual(len(pair.receiver.page(after=0, limit=10)), 1)
        revocation = next(
            event
            for event in pair.history
            if event["kind"] == "matrix/relationship-grant-revocation"
        )
        pair.receiver_relationships.ingest(revocation)
        pair.now = NOW + 17
        before = pair.store_path.read_bytes()
        with patch.object(
            pair.receiver_custody, "unwrap", wraps=pair.receiver_custody.unwrap
        ) as unwrap:
            with self.assertRaises(ValueError):
                pair.receiver.receive_evidence(evidence)
            with self.assertRaises(ValueError):
                pair.receiver.receive_message(message)
            with self.assertRaises(ValueError):
                pair.receiver.page(after=0, limit=10)
            unwrap.assert_not_called()
        self.assertEqual(pair.store_path.read_bytes(), before)

    def test_manual_read_rejects_mismatched_signed_evidence(self) -> None:
        import sqlite3

        from daimon_matrix.messaging_store import MessagingInboxError

        pair = Pair(self.root)
        wire, message_wire, _, _ = pair.wire()
        pair.receiver.receive_evidence(wire)
        pair.receiver.receive_message(message_wire)
        _, _, _, unrelated = pair.wire(200)
        with closing(sqlite3.connect(pair.store_path)) as database, database:
            database.execute(
                "UPDATE inbox SET evidence=?", (canonical_bytes(unrelated),)
            )
        with self.assertRaises(MessagingInboxError):
            pair.receiver.page(after=0, limit=10)
