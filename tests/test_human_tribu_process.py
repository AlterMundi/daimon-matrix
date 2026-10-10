"""Real TLS owner calls and real authenticated native reply-intent I/O."""

from __future__ import annotations

import json
import ssl
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.human_tribu import HumanTribu, HumanTribuError, document
from daimon_matrix.human_tribu_process import (
    CLIENT_SCHEMA,
    OwnerClient,
    TelegramIngress,
    _http,
    api_server,
)
from tests.test_dm022_ledger import NOW
from tests.test_dm025_client import ClientFixture
from tests.test_human_tribu import message, native_proof, person, response


class HumanProcessTests(ClientFixture):
    def setUp(self) -> None:
        super().setUp()
        self.person = person(self)
        self.store = HumanTribu(
            self.root_path / "human.sqlite",
            bot_id=123,
            chat_id=-123,
            participants=lambda: [self.person],
            clock=lambda: NOW,
        )
        self.sent: list[dict[str, Any]] = []
        self.ca = self.root_path / "ca.pem"
        tls_key = self.root_path / "tls.key"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test localhost")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        self.ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        tls_key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.ca.chmod(0o600)
        tls_key.chmod(0o600)
        fixture = self

        class BotHandler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                request = document(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/sendMessage":
                    raw = response(fixture.sent, request)
                elif self.path == "/getMe":
                    raw = canonical_bytes(
                        {
                            "ok": True,
                            "result": {
                                "id": 123,
                                "is_bot": True,
                                "can_read_all_group_messages": True,
                            },
                        }
                    )
                elif self.path == "/getChat":
                    raw = canonical_bytes(
                        {"ok": True, "result": {"id": -123, "type": "supergroup"}}
                    )
                elif self.path == "/getWebhookInfo":
                    raw = canonical_bytes({"ok": True, "result": {"url": ""}})
                elif self.path == "/getUpdates":
                    raw = canonical_bytes(
                        {"ok": False, "error_code": 409}
                        if request["offset"] == 99
                        else {"ok": True, "result": [message()]}
                    )
                else:
                    raw = canonical_bytes({"ok": False, "error_code": 409})
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        bot_server = ThreadingHTTPServer(("localhost", 0), BotHandler)
        bot_url = self.launch(bot_server, tls_key)
        ca = self.ca

        class TestIngress(TelegramIngress):
            def call(self, method: str, payload: Any) -> bytes:
                return _http(bot_url + "/" + method, payload, ca=ca)

        self.telegram = TestIngress(token="123:synthetic", bot_id=123, chat_id=-123)
        self.telegram.qualify()
        server = api_server(self.store, self.telegram, "localhost", 0)
        url = self.launch(server, tls_key)
        token = self.root_path / "client.token"
        token.write_text(self.person.token)
        token.chmod(0o600)
        client_key = self.root_path / "client.key"
        client_key.write_bytes(self.capability.key)
        client_key.chmod(0o600)
        requests = self.root_path / "requests"
        requests.mkdir(mode=0o700)
        settings = {
            "schema": CLIENT_SCHEMA,
            "being_ref": self.person.being_ref,
            "service_url": url,
            "service_ca": str(self.ca),
            "token_file": str(token),
            "native_binding": {
                "socket": str(self.runtime.socket_path),
                "client_config": str(self.config_path),
                "client_key": str(client_key),
            },
            "request_dir": str(requests),
            "native_ledger": str(self.ledger_a.path),
            "native_echo_stores": [],
        }
        self.owner_config = self.root_path / "owner.json"
        self.owner_config.write_bytes(canonical_bytes(settings))
        self.owner_config.chmod(0o600)
        self.owner = OwnerClient(self.owner_config)

    def launch(self, server: ThreadingHTTPServer, key: Path) -> str:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.ca), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def stop() -> None:
            server.shutdown()
            server.server_close()
            worker.join(5)

        self.addCleanup(stop)
        return "https://localhost:" + str(server.server_port)

    def test_real_passive_tls_manual_read_native_signed_reply_and_retry(self) -> None:
        events_before = len(self.runtime.service.ledger.events())
        for update in self.telegram.updates(None):
            self.store.ingest(update)
        self.assertEqual(len(self.runtime.service.ledger.events()), events_before)
        self.assertEqual(self.sent, [])
        page = self.owner.call("query", {"after": 0, "limit": 20})
        source = page["items"][0]
        operation = str(uuid.uuid4())
        # Keep fixture time on the actual authenticated Unix-socket client.
        with patch.object(self.owner, "_native", return_value=self.client()):
            result = self.owner.reply(
                source_id=source["id"],
                revision=source["revision"],
                text="A manual public response.",
                operation_id=operation,
            )
            retried = self.owner.retry(operation)
        self.assertEqual(result["state"], "confirmed")
        self.assertEqual(result, retried)
        self.assertEqual(self.owner.call("publication", {"id": operation}), result)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(len(self.runtime.service.ledger.events()), events_before + 1)
        self.assertEqual(result["event"]["origin"], self.person.origin)
        self.assertFalse(self.owner.call("status", {})["automatic_inference"])

    def test_manual_read_resolves_only_selected_native_public_parent(self) -> None:
        event, _proof = native_proof(self)
        catalog = self.root_path / "echo.sqlite"
        catalog.chmod(0o600)
        self.owner.settings["native_echo_stores"] = [str(catalog)]
        candidate = message(ident=20, text="Please look at this public answer")
        candidate["message"]["entities"] = []
        candidate["message"]["reply_to_message"] = {"message_id": 1}
        self.store.ingest(candidate)
        self.assertEqual(
            self.owner.call("query", {"after": 0, "limit": 20})["items"], []
        )
        before = len(self.runtime.service.ledger.events())
        result = self.owner.read()
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["context"]["event_id"], event["event_id"])
        self.assertEqual(
            self.owner.call("parents", {"after": 0, "limit": 100})["items"], []
        )
        self.assertEqual(len(self.runtime.service.ledger.events()), before)
        self.assertEqual(self.sent, [])

    def test_tls_and_scoped_identity_are_required(self) -> None:
        settings = json.loads(self.owner_config.read_bytes())
        settings["service_url"] = settings["service_url"].replace("https:", "http:")
        self.owner_config.write_bytes(canonical_bytes(settings))
        with self.assertRaisesRegex(HumanTribuError, "endpoint_invalid"):
            OwnerClient(self.owner_config)
        with self.assertRaisesRegex(HumanTribuError, "unauthorized"):
            self.owner.token = "b" * 64
            self.owner.call("query", {"after": 0, "limit": 20})

    def test_existing_consumer_conflict_is_explicit_and_does_not_acknowledge(
        self,
    ) -> None:
        with self.assertRaisesRegex(HumanTribuError, "telegram_consumer_conflict"):
            self.telegram.updates(99)
        self.assertIsNone(self.store.status()["last_update_id"])
