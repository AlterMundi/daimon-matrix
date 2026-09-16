"""Offline native mirror tests; Telegram is always mocked."""

import tempfile
import unittest
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock, patch

from daimon_matrix import telegram_mirror as mirror


class MirrorTests(unittest.TestCase):
    def message(self, text: str = "hello <&>") -> mirror.MirrorMessage:
        return mirror.MirrorMessage(
            event_id="event-1",
            event_digest="a" * 64,
            authorization_digest="b" * 64,
            sender="Alice",
            channel="Agreed channel",
            thread_id="thread-1",
            text=text,
        )

    def test_render_escapes_and_chunks_without_source_provenance(self) -> None:
        message = self.message("<&😀" * 2500)
        parts = mirror.render_parts(message)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(len(p.encode("utf-16-le")) // 2 <= 4096 for p in parts))
        self.assertIn("&lt;&amp;😀", parts[0])
        self.assertIn("part 1/", parts[0])
        self.assertIn("Daimon Matrix", parts[0])
        self.assertNotIn(message.event_digest, "".join(parts))
        self.assertEqual(
            "".join(p.split("</b>\n", 1)[1] for p in parts),
            __import__("html").escape(message.text),
        )

    def adapter(
        self,
        path: Path,
        message: mirror.MirrorMessage | None = None,
        verifier: Callable[..., Any] | None = None,
        chat: int = -123,
    ) -> mirror.TelegramMirror:
        message = message or self.message()
        binding = mirror.SharingBinding(
            policy_digest="c" * 64,
            event_digest=message.event_digest,
            authorization_digest=message.authorization_digest,
            chat_id=chat,
        )
        return mirror.TelegramMirror(
            resolver=Mock(return_value=message),
            verify_sharing=verifier or Mock(return_value=binding),
            enabled=True,
            token="123:TEST_SECRET",
            chat_id=chat,
            policy_digest="c" * 64,
            state_path=path,
        )

    @patch("urllib.request.OpenerDirector.open")
    def test_send_confirmed_is_durable_and_minimal(self, send: Mock) -> None:
        send.return_value.__enter__.return_value.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            adapter = self.adapter(path)
            self.assertEqual(
                adapter.mirror_selected("event-1")["status"], "delivered-to-platform"
            )
            self.assertEqual(
                self.adapter(path).mirror_selected("event-1")["status"],
                "delivered-to-platform",
            )
            self.assertEqual(send.call_count, 1)
            request = send.call_args.args[0]
            payload = __import__("json").loads(request.data)
            self.assertEqual(
                set(payload),
                {"chat_id", "text", "parse_mode", "disable_web_page_preview"},
            )
            self.assertNotIn("TEST_SECRET", repr(adapter))
            self.assertNotIn(b"hello", path.read_bytes())
            self.assertNotIn(b"TEST_SECRET", path.read_bytes())

    @patch("urllib.request.OpenerDirector.open")
    def test_authority_is_not_a_boolean_or_stale_binding(self, send: Mock) -> None:
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            for evidence in (
                None,
                True,
                mirror.SharingBinding("c" * 64, "a" * 64, "b" * 64, -999),
            ):
                adapter = self.adapter(path, verifier=Mock(return_value=evidence))
                self.assertEqual(
                    adapter.mirror_selected("event-1")["status"], "rejected"
                )
            adapter = self.adapter(path)
            cast(Mock, adapter._resolver).side_effect = ValueError(
                "private-source-SECRET"
            )
            self.assertEqual(adapter.mirror_selected("event-1"), {"status": "rejected"})
            adapter = self.adapter(
                path, message=replace(self.message(), event_id="other")
            )
            self.assertEqual(adapter.mirror_selected("event-1")["status"], "rejected")
            send.assert_not_called()
            self.assertFalse(path.exists())

    @patch("urllib.request.OpenerDirector.open")
    def test_ambiguous_part_resumes_without_resending_confirmed_parts(
        self, send: Mock
    ) -> None:
        import sqlite3

        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        send.side_effect = [
            response,
            OSError("https://api.telegram.org/botTEST_SECRET"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            message = self.message("x" * 4500)
            adapter = self.adapter(path, message)
            result = adapter.mirror_selected("event-1")
            self.assertEqual(result["status"], "pending")
            self.assertTrue(result["ambiguous"])
            self.assertEqual(result["confirmed_parts"], 1)
            self.assertNotIn("TEST_SECRET", repr(result))
            with closing(sqlite3.connect(path)) as db:
                progress = __import__("json").loads(
                    db.execute("SELECT progress FROM mirror_progress").fetchone()[0]
                )
            self.assertEqual(progress, [91, "pending"])
            send.side_effect = [response]
            self.assertEqual(
                self.adapter(path, message).mirror_selected("event-1")["status"],
                "delivered-to-platform",
            )
            self.assertEqual(send.call_count, 3)
            self.assertIn(
                "part 2/2",
                __import__("json").loads(send.call_args.args[0].data)["text"],
            )

    @patch("urllib.request.OpenerDirector.open")
    def test_durable_binding_rejects_content_chat_policy_and_authority_changes(
        self, send: Mock
    ) -> None:
        from dataclasses import replace

        send.return_value.__enter__.return_value.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            self.adapter(path).mirror_selected("event-1")
            candidates = [
                self.adapter(path, replace(self.message(), text="changed")),
                self.adapter(path, chat=-999),
                self.adapter(
                    path, replace(self.message(), authorization_digest="d" * 64)
                ),
            ]
            adapter = self.adapter(path)
            adapter._policy_digest = "e" * 64
            cast(Mock, adapter._verify_sharing).return_value = mirror.SharingBinding(
                "e" * 64, "a" * 64, "b" * 64, -123
            )
            candidates.append(adapter)
            for adapter in candidates:
                self.assertEqual(
                    adapter.mirror_selected("event-1")["status"], "conflict"
                )
            self.assertEqual(send.call_count, 1)

    @patch("urllib.request.OpenerDirector.open")
    def test_revocation_between_parts_prevents_next_io(self, send: Mock) -> None:
        send.return_value.__enter__.return_value.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            message = self.message("x" * 4500)
            adapter = self.adapter(Path(directory) / "mirror.sqlite", message)
            cast(Mock, adapter._resolver).side_effect = [
                message,
                message,
                ValueError("revoked"),
            ]
            self.assertEqual(adapter.mirror_selected("event-1")["status"], "rejected")
            self.assertEqual(send.call_count, 1)

    @patch("urllib.request.OpenerDirector.open")
    def test_bounded_render_suppresses_oversize_without_io(self, send: Mock) -> None:
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            for message in (
                self.message("x" * 65537),
                replace(self.message(), sender="<&" * 3000),
            ):
                self.assertEqual(
                    self.adapter(path, message).mirror_selected("event-1")["status"],
                    "suppressed",
                )
            send.assert_not_called()
            self.assertFalse(path.exists())

    @patch("urllib.request.OpenerDirector.open")
    def test_config_and_projection_are_strictly_validated(self, send: Mock) -> None:
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            for field, value in (
                ("_enabled", "yes"),
                ("_chat_id", True),
                ("_token", "bad/token?secret"),
                ("_policy_digest", "bad"),
            ):
                adapter = self.adapter(path)
                setattr(adapter, field, value)
                self.assertEqual(
                    adapter.mirror_selected("event-1")["status"], "rejected"
                )
            adapter = self.adapter(path, replace(self.message(), event_digest="bad"))
            self.assertEqual(adapter.mirror_selected("event-1")["status"], "rejected")
            send.assert_not_called()

    @patch("urllib.request.OpenerDirector.open")
    def test_state_is_owner_only_bounded_and_single_flight(self, send: Mock) -> None:
        import fcntl
        import os

        send.return_value.__enter__.return_value.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            self.adapter(path).mirror_selected("event-1")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with path.open("rb") as locked:
                fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(
                    self.adapter(path).mirror_selected("event-1")["status"], "busy"
                )
            with patch.object(mirror, "MAX_RECORDS", 1):
                from dataclasses import replace

                adapter = self.adapter(
                    path, replace(self.message(), event_id="event-2")
                )
                self.assertEqual(
                    adapter.mirror_selected("event-2")["status"], "capacity"
                )
                self.assertEqual(
                    self.adapter(path).mirror_selected("event-1")["status"],
                    "delivered-to-platform",
                )
            os.chmod(path, 0o644)
            self.assertEqual(
                self.adapter(path).mirror_selected("event-1")["status"], "unavailable"
            )
            self.assertEqual(send.call_count, 1)

    @patch("urllib.request.OpenerDirector.open")
    def test_invalid_platform_responses_never_confirm(self, send: Mock) -> None:
        import http.client
        import json

        for value in (
            {"ok": False, "result": {"message_id": 91}},
            {"ok": True, "result": {"message_id": True, "chat": {"id": -123}}},
            {"ok": True, "result": {"message_id": 91, "chat": {"id": -999}}},
            {"ok": True, "result": {"message_id": -1, "chat": {"id": -123}}},
        ):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                send.return_value.__enter__.return_value.read.return_value = json.dumps(
                    value
                ).encode()
                result = self.adapter(
                    Path(directory) / "mirror.sqlite"
                ).mirror_selected("event-1")
                self.assertEqual(result["status"], "pending")
                self.assertEqual(result["confirmed_parts"], 0)
        for error in (http.client.IncompleteRead(b"private"), TimeoutError("token")):
            with tempfile.TemporaryDirectory() as directory:
                send.side_effect = error
                result = self.adapter(
                    Path(directory) / "mirror.sqlite"
                ).mirror_selected("event-1")
                self.assertTrue(result["ambiguous"])
                self.assertNotIn("private", repr(result))

    @patch("urllib.request.OpenerDirector.open")
    def test_malformed_progress_fails_closed_without_resend(self, send: Mock) -> None:
        import sqlite3

        send.return_value.__enter__.return_value.read.return_value = (
            b'{"ok":true,"result":{"message_id":91,"chat":{"id":-123}}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mirror.sqlite"
            self.adapter(path).mirror_selected("event-1")
            for malformed in ("[true]", "[0]", "[91, 92]", "{}", '["confirmed"]'):
                with closing(sqlite3.connect(path)) as db:
                    db.execute("UPDATE mirror_progress SET progress=?", (malformed,))
                    db.commit()
                self.assertEqual(
                    self.adapter(path).mirror_selected("event-1")["status"],
                    "unavailable",
                )
            self.assertEqual(send.call_count, 1)

    def test_disabled_by_default(self) -> None:
        resolver, verifier = Mock(), Mock()
        adapter = mirror.TelegramMirror(resolver=resolver, verify_sharing=verifier)
        self.assertEqual(adapter.mirror_selected("selected"), {"status": "disabled"})
        resolver.assert_not_called()
        verifier.assert_not_called()


class MandatoryPlainTests(unittest.TestCase):
    def test_explicit_bot_api_rejection_is_not_ambiguous_acceptance(self):
        import json

        request = mirror.plain_request("hello", chat_id=-123, topic_id=None)
        for code in (400, 401, 403, 404, 409, 429):
            raw = json.dumps(
                {
                    "ok": False,
                    "error_code": code,
                    "description": "synthetic rejection",
                    "parameters": {"retry_after": 2},
                }
            ).encode()
            self.assertEqual(
                mirror.classify_plain_response(raw, request, bot_id=123),
                ("rejected", 2),
            )
        for raw in (
            b'{"ok":false,"error_code":500,"description":"uncertain"}',
            b'{"ok":false,"error_code":429,"description":"x","parameters":{"retry_after":true}}',
            b'{"ok":false,"error_code":429,"description":"x","parameters":{"migrate_to_chat_id":-999}}',
        ):
            with self.assertRaisesRegex(ValueError, "echo_response_invalid"):
                mirror.classify_plain_response(raw, request, bot_id=123)

    def test_transport_rejects_boolean_aliases_before_network(self):
        transport = mirror.PlainTelegramTransport(
            token="123:TEST_ONLY", bot_id=123, chat_id=1, topic_id=1
        )
        request = mirror.plain_request("hello", chat_id=1, topic_id=1)
        for malformed in (
            {**request, "chat_id": True},
            {**request, "message_thread_id": True},
            {**request, "link_preview_options": {"is_disabled": 1}},
        ):
            with patch("urllib.request.OpenerDirector.open") as opened:
                with self.assertRaisesRegex(ValueError, "^echo_request_invalid$"):
                    transport.send(malformed)
                opened.assert_not_called()

    def test_invalid_evidence_is_closed_and_duplicate_keys_rejected(self) -> None:
        import copy
        import json

        request = mirror.plain_request("hello", chat_id=-123, topic_id=None)
        value = {
            "ok": True,
            "result": {
                "message_id": 9,
                "from": {"id": 123, "is_bot": True},
                "chat": {"id": -123},
                "text": "hello",
            },
        }
        mutations = [
            ("text", "other"),
            ("message_id", True),
            ("message_thread_id", None),
            ("message_thread_id", 7),
            ("is_topic_message", True),
            ("from", {"id": 123, "is_bot": False}),
            ("from", {"id": 999, "is_bot": True}),
            ("chat", {"id": -999}),
            (
                "entities",
                [
                    {
                        "type": "text_link",
                        "offset": 0,
                        "length": 5,
                        "url": "https://example.org",
                    }
                ],
            ),
        ]
        for field, bad in mutations:
            altered = copy.deepcopy(value)
            altered["result"][field] = bad
            with (
                self.subTest(field=field, bad=bad),
                self.assertRaisesRegex(ValueError, "^echo_response_invalid$"),
            ):
                mirror.validate_plain_response(
                    json.dumps(altered).encode(), request, bot_id=123
                )
        raw = (
            json.dumps(value).replace('"ok": true', '"ok": false, "ok": true').encode()
        )
        with self.assertRaisesRegex(ValueError, "^echo_response_invalid$"):
            mirror.validate_plain_response(raw, request, bot_id=123)

    def test_real_http_transport_retains_response_and_sanitizes_truncation(
        self,
    ) -> None:
        import json
        import threading
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = []
        truncate = [False]
        reject = [False]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                seen.append(payload)
                raw = json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "message_id": 9,
                            "from": {"id": 123, "is_bot": True},
                            "chat": {"id": -123},
                            "text": payload["text"],
                        },
                    }
                ).encode()
                if reject[0]:
                    raw = (
                        b'{"ok":false,"error_code":429,"description":"synthetic busy",'
                        b'"parameters":{"retry_after":2}}'
                    )
                self.send_response(429 if reject[0] else 200)
                self.send_header(
                    "Content-Length", str(len(raw) + (100 if truncate[0] else 0))
                )
                self.end_headers()
                self.wfile.write(raw)
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        original = urllib.request.OpenerDirector.open

        def local_open(opener, request, *args, **kwargs):
            self.assertEqual(
                request.full_url,
                "https://api.telegram.org/bot123:TEST_ONLY/sendMessage",
            )
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/sendMessage",
                data=request.data,
                headers=dict(request.headers),
                method=request.method,
            )
            return original(opener, request, *args, **kwargs)

        try:
            with patch("urllib.request.OpenerDirector.open", local_open):
                transport = mirror.PlainTelegramTransport(
                    token="123:TEST_ONLY", bot_id=123, chat_id=-123, topic_id=None
                )
                request = mirror.plain_request("hello", chat_id=-123, topic_id=None)
                raw = transport.send(request)
                self.assertEqual(
                    mirror.validate_plain_response(raw, request, bot_id=123)["result"][
                        "text"
                    ],
                    "hello",
                )
                truncate[0] = True
                with self.assertRaisesRegex(ValueError, "^echo_transport_ambiguous$"):
                    transport.send(request)
                with self.assertRaisesRegex(ValueError, "^echo_request_invalid$"):
                    transport.send({**request, "chat_id": -999})
                self.assertEqual(len(seen), 2)
                truncate[0] = False
                reject[0] = True
                negative = transport.send(request)
                self.assertEqual(
                    mirror.classify_plain_response(negative, request, bot_id=123),
                    ("rejected", 2),
                )
                self.assertEqual(len(seen), 3)
                self.assertNotIn("TEST_ONLY", repr(transport))
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_complete_plaintext_parts_and_verified_response(self) -> None:
        import json

        document = "<&😀\n" * 1600
        parts = mirror.render_plain_parts(document)
        self.assertGreater(len(parts), 1)
        self.assertEqual("".join(p.split("\n", 1)[1] for p in parts), document)
        self.assertTrue(all(len(p.encode("utf-16-le")) // 2 <= 4096 for p in parts))
        request = mirror.plain_request(parts[0], chat_id=-123, topic_id=7)
        self.assertNotIn("parse_mode", request)
        raw = json.dumps(
            {
                "ok": True,
                "result": {
                    "message_id": 9,
                    "from": {"id": 123, "is_bot": True},
                    "chat": {"id": -123},
                    "message_thread_id": 7,
                    "is_topic_message": True,
                    "text": parts[0],
                },
            }
        ).encode()
        self.assertEqual(
            mirror.validate_plain_response(raw, request, bot_id=123)["result"][
                "message_id"
            ],
            9,
        )


if __name__ == "__main__":
    unittest.main()
