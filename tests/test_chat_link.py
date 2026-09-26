"""Real-crypto owner-invoked enrollment with disposable identities, no network."""

import copy
import tempfile
import unittest
from pathlib import Path

from daimon_matrix.native_egress import closed_visibility
from daimon_matrix.relationship_store import RelationshipStore
from daimon_matrix.runtime import load_runtime, verify_relationship_card_authority
from tools.chat_link import (
    decrypt_packet,
    disclosures,
    encrypt_packet,
    install_link,
    make_plan,
    now,
    policies,
    read_public,
    sign_proposals,
    verify_identity,
)
from tools.prepare_chat_identity import prepare


class ChatLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="dm-link-")
        cls.root = Path(cls.temp.name).resolve()
        cls.public = []
        cls.runtimes = []
        for i in range(2):
            output = cls.root / str(i)
            path = prepare(
                output,
                label=f"peer-{i}",
                body_ref=f"hermes:peer-{i}",
                principal_id=f"peer-{i}",
            )
            cls.public.append(read_public(path))
            password = (output / "body.password").read_bytes()
            cls.runtimes.append(
                load_runtime(
                    output / "package/runtime",
                    "runtime.json",
                    lambda p=password: bytearray(p),
                    clock=now,
                    egress=closed_visibility(clock=now, catalog_mode="migrate"),
                )
            )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def plan(self):
        return make_plan(
            self.runtimes[0],
            *self.public,
            ["http://127.0.0.1:28686", "http://127.0.0.1:28687"],
            {
                "bot_id": 123,
                "chat_id": -100123,
                "topic_id": None,
                "representation": "plain-json/v2",
            },
        )

    def test_identity_binding_and_history_are_verified(self):
        for item in self.public:
            self.assertEqual(len(verify_identity(item).historical), 1)
        changed = copy.deepcopy(self.public[1])
        changed["document"]["runtime_label"] = "forged"
        with self.assertRaises(ValueError):
            verify_identity(changed)

    def test_drafts_need_real_peer_signature_and_form_active_relationship(self):
        plan = self.plan()
        remote = self.public[1]["document"]["authority"]["manifest"]["being_ref"]
        for event in plan["events"]:
            self.assertEqual("signature" in event, event["being_ref"] != remote)
        signed = sign_proposals(self.runtimes[1], plan, 1)
        authorities = {a.state.being_ref: a for a in map(verify_identity, self.public)}
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            store = RelationshipStore(
                Path(directory) / "relations.sqlite",
                authority_resolver=authorities.__getitem__,
            )
            for event in signed:
                store.ingest(event)
            view = store.view(
                at_ms=now(),
                card_verifier=lambda card, at: verify_relationship_card_authority(
                    card, authorities[card["being_ref"]], at_ms=at
                ),
            )
            snapshot = view.snapshot(plan["tribe_ref"])
            self.assertEqual(len(snapshot.value["members"]), 2)
            self.assertEqual(len(snapshot.value["grants"]), 2)
            self.assertEqual(len(policies(plan)), 2)
        self.assertEqual(self.runtimes[1].service.ledger.events(), [])

    def test_packet_is_recipient_encrypted_and_sender_authenticated(self):
        secret = "disposable-transport-test-material"
        packet = encrypt_packet(self.runtimes[0], self.public[1], {"secret": secret})
        self.assertNotIn(secret, str(packet))
        self.assertEqual(
            decrypt_packet(self.runtimes[1], self.public[0], packet), {"secret": secret}
        )
        tampered = copy.deepcopy(packet)
        tampered["document"]["ciphertext"] = "AAAA"
        with self.assertRaises(ValueError):
            decrypt_packet(self.runtimes[1], self.public[0], tampered)
        with self.assertRaises(ValueError):
            decrypt_packet(self.runtimes[0], self.public[0], packet)

    def test_wrong_local_identity_and_modified_draft_are_refused(self):
        plan = self.plan()
        with self.assertRaises(ValueError):
            sign_proposals(self.runtimes[0], plan, 1)
        plan["events"][1]["payload"]["issued_at_ms"] += 1
        with self.assertRaises(ValueError):
            sign_proposals(self.runtimes[1], plan, 1)

    def test_complete_signed_install_and_retry_without_network(self):
        import hashlib
        import secrets
        import select
        import subprocess
        import sys
        from unittest.mock import patch

        from daimon_matrix.canonical import b64url
        from daimon_matrix.messaging_config import create_binding
        from tools.chat_link import accept, finish, put

        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            root = Path(directory)
            runtimes, public, passwords = [], [], []
            for i in range(2):
                path = prepare(
                    root / str(i),
                    label=f"install-{i}",
                    body_ref=f"hermes:install-{i}",
                    principal_id=f"install-{i}",
                )
                public.append(read_public(path))
                passwords.append((root / str(i) / "body.password").read_bytes())
                runtimes.append(
                    load_runtime(
                        root / str(i) / "package/runtime",
                        "runtime.json",
                        lambda i=i: bytearray(passwords[i]),
                        clock=now,
                        egress=closed_visibility(clock=now, catalog_mode="migrate"),
                    )
                )
            plan = make_plan(
                runtimes[0],
                *public,
                ["http://127.0.0.1:28686", "http://127.0.0.1:28687"],
                {
                    "bot_id": 123,
                    "chat_id": -100123,
                    "topic_id": None,
                    "representation": "plain-json/v2",
                },
            )
            token = b"123:synthetic-unit-test-token"
            payload = {
                "plan": plan,
                "signed_events": sign_proposals(runtimes[1], plan, 1),
                "route_keys": {
                    f"{i}-{p}.key": b64url(secrets.token_bytes(32))
                    for i in range(2)
                    for p in ("evidence", "message")
                },
                "telegram_token": b64url(token),
                "telegram_qualification": {
                    "schema": "dm.messaging.telegram-qualification/v1",
                    "qualified_at_ms": now(),
                    "token_sha256": hashlib.sha256(token).hexdigest(),
                    "get_me_bot_id": 123,
                    "probe_chat_id": -100123,
                    "probe_topic_id": None,
                    "probe_message_id": 1,
                    "probe_text_sha256": "b" * 64,
                },
                "visibility_bindings": [
                    [create_binding(r, d) for d in disclosures(plan)] for r in runtimes
                ],
            }
            with patch(
                "socket.create_connection", side_effect=AssertionError("no network")
            ):
                pending = copy.deepcopy(payload)
                del pending["signed_events"]
                pending["visibility_bindings"][1] = []
                outputs = [root / f"link-{i}" for i in range(2)]
                for output in outputs:
                    output.mkdir(mode=0o700)
                put(outputs[0] / "pending.json", pending)
                packet = {
                    "sender_identity": public[0],
                    "packet": encrypt_packet(runtimes[0], public[1], pending),
                }
                response_path = accept(
                    runtimes[1],
                    root / "1/package/runtime",
                    passwords[1],
                    packet,
                    outputs[1],
                )
                response = read_public(response_path)
                finish(
                    runtimes[0],
                    root / "0/package/runtime",
                    passwords[0],
                    response,
                    outputs[0],
                )
                self.assertNotIn("telegram_token", str(response))
                self.assertNotIn("route_keys", str(response))
                self.assertEqual(
                    response_path,
                    accept(
                        runtimes[1],
                        root / "1/package/runtime",
                        passwords[1],
                        packet,
                        outputs[1],
                    ),
                )
                finish(
                    runtimes[0],
                    root / "0/package/runtime",
                    passwords[0],
                    response,
                    outputs[0],
                )
                tampered = copy.deepcopy(response)
                tampered["document"]["plan_sha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    finish(
                        runtimes[0],
                        root / "0/package/runtime",
                        passwords[0],
                        tampered,
                        outputs[0],
                    )
                payload = read_public(outputs[0] / "completed-private.json")
                for i in range(2):
                    output = root / f"link-{i}"
                    result = install_link(
                        root / str(i) / "package/runtime",
                        passwords[i],
                        output,
                        payload,
                        i,
                    )

                    self.assertEqual(result["inbox_reads"], 0)
                    self.assertEqual(result["services_started"], 0)
                    self.assertEqual(
                        result,
                        install_link(
                            root / str(i) / "package/runtime",
                            passwords[i],
                            output,
                            payload,
                            i,
                        ),
                    )
                # Start the real transport once, with no inbox/model invocation.
                ready_path = outputs[1] / "ready.json"
                command = [
                    sys.executable,
                    "-c",
                    "import faulthandler,runpy,sys; "
                    "faulthandler.dump_traceback_later(20,file=sys.stdout); "
                    "runpy.run_path('tools/chat_link.py',run_name='__main__')",
                    "run",
                    "--runtime-root",
                    str(root / "1/package/runtime"),
                    "--password-file",
                    str(root / "1/body.password"),
                    "--output",
                    str(outputs[1]),
                    "--input",
                    str(ready_path),
                    "--sha256",
                    hashlib.sha256(ready_path.read_bytes()).hexdigest(),
                ]
                with subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
                ) as process:
                    available, _, _ = select.select([process.stderr], [], [], 25)
                    line = process.stderr.readline() if available else b""
                    running = process.poll() is None
                    try:
                        process.terminate()
                        trace, diagnostics = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        trace, diagnostics = process.communicate(timeout=5)
                    self.assertIn(b'"code":"ready"', line, line + trace + diagnostics)
                    self.assertTrue(running)
                    self.assertEqual(process.returncode, 0, diagnostics)

    def test_cli_help_and_endpoint_validation(self):
        import subprocess
        import sys

        from tools.chat_link import validate_endpoints

        completed = subprocess.run(
            [sys.executable, "tools/chat_link.py", "--help"],
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for endpoints in (
            ["http://0.0.0.0:8686", "http://127.0.0.1:8686"],
            ["http://127.0.0.1:8686/a", "http://127.0.0.1:8687"],
            ["http://127.0.0.1:22", "http://127.0.0.1:8687"],
        ):
            with self.assertRaises(ValueError):
                validate_endpoints(endpoints)

    def test_transport_bind_does_not_require_reverse_dns(self):
        from http.server import BaseHTTPRequestHandler
        from unittest.mock import patch

        from daimon_matrix.daemon import (
            _BoundedMessagingHTTPServer,
            _BoundedPeerHTTPServer,
        )

        with patch("socket.getfqdn", side_effect=AssertionError("DNS unavailable")):
            for server_class in (_BoundedPeerHTTPServer, _BoundedMessagingHTTPServer):
                with server_class(("127.0.0.1", 0), BaseHTTPRequestHandler) as server:
                    self.assertEqual(server.server_name, "127.0.0.1")
                    self.assertGreater(server.server_port, 0)


if __name__ == "__main__":
    unittest.main()
