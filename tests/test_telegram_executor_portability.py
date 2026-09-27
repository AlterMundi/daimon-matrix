"""Real local HTTP and PTY lifetime tests; no Telegram credentials or traffic."""

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from daimon_matrix import telegram_mirror as mirror
from tests import test_telegram_mirror as baseline


class TerminalExecutorTests(unittest.TestCase):
    def test_real_http_and_response_validation(self):
        with patch.object(mirror, "_plain_lifetime_mode", return_value="terminal"):
            baseline.MandatoryPlainTests.test_real_http_transport_retains_response_and_sanitizes_truncation(
                self
            )

    def test_timeout_and_interruption_reap_executor(self):
        with patch.object(mirror, "_plain_lifetime_mode", return_value="terminal"):
            baseline.MandatoryPlainTests.test_deadline_covers_dns_and_interruption_reaps_child(
                self
            )

    def test_slow_http_stays_bounded(self):
        with patch.object(mirror, "_plain_lifetime_mode", return_value="terminal"):
            baseline.MandatoryPlainTests.test_total_deadline_slow_headers_body_and_chunk_framing(
                self
            )

    def test_launch_failure_closes_both_terminal_descriptors(self):
        opened = []
        original = os.openpty

        def allocate():
            pair = original()
            opened.extend(pair)
            return pair

        with (
            patch.object(mirror, "_plain_lifetime_mode", return_value="terminal"),
            patch.object(os, "openpty", allocate),
            patch.object(subprocess, "Popen", side_effect=OSError("fixture failure")),
            self.assertRaises(OSError),
        ):
            mirror._plain_http_exchange("http://127.0.0.1:1/", b"{}")
        self.assertEqual(len(opened), 2)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_platform_selection_and_unsupported_no_spawn(self):
        for platform, mode in (("linux", "linux"), ("darwin", "terminal")):
            with patch.object(mirror.sys, "platform", platform):
                self.assertEqual(mirror._plain_lifetime_mode(), mode)
        with (
            patch.object(mirror.sys, "platform", "unsupported"),
            patch.object(subprocess, "Popen") as launch,
            self.assertRaisesRegex(ValueError, "platform_unsupported"),
        ):
            mirror._plain_http_exchange("http://127.0.0.1:1/", b"{}")
        launch.assert_not_called()

    def test_hard_parent_death_hangs_up_executor_despite_inherited_signal_mask(self):
        received = threading.Event()
        disconnected = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                received.set()
                self.connection.settimeout(3)
                try:
                    if self.rfile.read(1) == b"":
                        disconnected.set()
                except TimeoutError:
                    pass
                self.close_connection = True

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        code = f"""
import signal
from daimon_matrix import telegram_mirror as t
signal.signal(signal.SIGHUP, signal.SIG_IGN)
signal.pthread_sigmask(signal.SIG_BLOCK, {{signal.SIGHUP}})
t._plain_lifetime_mode = lambda: "terminal"
t._plain_http_exchange("http://127.0.0.1:{server.server_port}/", b"{{}}")
"""
        try:
            with subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ) as parent:
                try:
                    self.assertTrue(
                        received.wait(5), "executor never reached local HTTP"
                    )
                    parent.kill()
                    parent.wait(timeout=3)
                    self.assertTrue(
                        disconnected.wait(2), "HTTP executor survived parent"
                    )
                finally:
                    if parent.poll() is None:
                        parent.kill()
                    parent.wait(timeout=3)
        finally:
            server.shutdown()
            worker.join(timeout=5)
            server.server_close()

    def test_wrong_parent_and_nonterminal_fd_refuse_before_http(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            for terminal, parent, succeeds in (
                (True, 0, False),
                (False, os.getpid(), False),
                (True, os.getpid(), True),
            ):
                with self.subTest(terminal=terminal, parent=parent):
                    first, second = os.openpty() if terminal else os.pipe()
                    try:
                        before = len(requests)
                        with subprocess.Popen(
                            [
                                sys.executable,
                                "-I",
                                str(Path(mirror.__file__).resolve()),
                            ],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            pass_fds=(second,),
                            env={},
                        ) as child:
                            out, err = child.communicate(
                                json.dumps(
                                    [
                                        parent,
                                        f"http://127.0.0.1:{server.server_port}/",
                                        "{}",
                                        second,
                                    ]
                                ).encode(),
                                timeout=3,
                            )
                            self.assertEqual(child.returncode == 0, succeeds)
                            self.assertEqual(bool(out), succeeds)
                            self.assertEqual(err, b"")
                            self.assertEqual(len(requests) - before, int(succeeds))
                    finally:
                        os.close(first)
                        os.close(second)
        finally:
            server.shutdown()
            worker.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
