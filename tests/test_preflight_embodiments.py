"""Preflight that reports which active embodiments are servable, read-only."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import socket
import tempfile
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tools.preflight_embodiments import (
    ABSENT,
    INCONCLUSIVE,
    PEER_PATH,
    SERVES,
    probe,
)
from tools.preflight_embodiments import (
    main as preflight_main,
)


class _Preflight:
    """Namespace so the assertions below read the same as the module constants."""

    SERVES = SERVES
    ABSENT = ABSENT
    INCONCLUSIVE = INCONCLUSIVE
    PEER_PATH = PEER_PATH
    main = staticmethod(preflight_main)
    probe = staticmethod(probe)


preflight = _Preflight

BEING = "dm:being:v1:" + "A" * 43


def _row(
    embodiment: str, incarnation: str, body_ref: str, *, status: str = "active"
) -> dict[str, Any]:
    return {
        "body_ref": body_ref,
        "embodiment_credential_id": f"cred:{embodiment}",
        "embodiment_id": embodiment,
        "incarnation_authorization_id": f"auth:{incarnation}",
        "incarnation_id": incarnation,
        "status": status,
    }


def _runtime(
    root: pathlib.Path,
    name: str,
    rows: list[dict[str, Any]],
    *,
    origin: tuple[str, str] | None = None,
    targets: list[tuple[str, str]] | None = None,
    listen: tuple[str, int] | None = None,
    revision: int = 1,
    extra_files: dict[str, bytes] | None = None,
) -> pathlib.Path:
    state = root / name
    state.mkdir(mode=0o700)
    transport: dict[str, Any] | None = None
    if targets is not None or listen is not None:
        transport = {
            "enabled": True,
            "listen_host": (listen or ("127.0.0.1", 1))[0],
            "listen_port": (listen or ("127.0.0.1", 1))[1],
            "targets": [
                {"embodiment_id": t, "endpoint": e, "timeout_ms": 1000}
                for t, e in (targets or [])
            ],
        }
    bundle = {
        "schema": "dm.runtime.bundle/v8",
        "manifest": {
            "being_ref": BEING,
            "revision": revision,
            "embodiments": rows,
        },
        "local_origin": (
            None
            if origin is None
            else {"embodiment_id": origin[0], "incarnation_id": origin[1]}
        ),
        "peer_transport": transport,
    }
    (state / "runtime.json").write_bytes(json.dumps(bundle).encode())
    for filename, raw in (extra_files or {}).items():
        (state / filename).write_bytes(raw)
    return state


def _run(argv: list[str]) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = preflight.main(argv)
    return code, json.loads(out.getvalue())


class PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_unservable_active_embodiment_fails_and_is_named(self) -> None:
        rows = [
            _row("embodiment:live", "incarnation:live", "cli:legion:body-a"),
            _row("embodiment:ghost", "incarnation:ghost", "cluster:legion:body-b"),
            _row("embodiment:far", "incarnation:far", "cluster:other:body-c"),
        ]
        state = _runtime(
            self.root, "a", rows, origin=("embodiment:live", "incarnation:live")
        )
        code, report = _run(["--host", "legion", "--runtime", str(state)])
        self.assertEqual(code, 1)
        self.assertFalse(report["enrollable"])
        self.assertEqual(report["unservable"], ["embodiment:ghost"])
        by_id = {row["embodiment_id"]: row for row in report["active"]}
        self.assertEqual(by_id["embodiment:live"]["servable"], "here")
        self.assertEqual(by_id["embodiment:ghost"]["servable"], "none")
        # a body that lives on another host is not judged by this host's preflight
        self.assertEqual(by_id["embodiment:far"]["servable"], "remote")
        self.assertTrue(
            any("embodiment:ghost" in reason for reason in report["reasons"]),
            report["reasons"],
        )

    def test_every_active_servable_exits_zero(self) -> None:
        rows = [
            _row("embodiment:one", "incarnation:one", "cli:legion:body-a"),
            _row("embodiment:two", "incarnation:two", "codex:legion:body-b"),
        ]
        first = _runtime(
            self.root, "a", rows, origin=("embodiment:one", "incarnation:one")
        )
        second = _runtime(
            self.root, "b", rows, origin=("embodiment:two", "incarnation:two")
        )
        code, report = _run(
            ["--host", "legion", "--runtime", str(first), "--runtime", str(second)]
        )
        self.assertEqual(code, 0)
        self.assertTrue(report["enrollable"])
        self.assertEqual(report["unservable"], [])
        self.assertEqual(report["reasons"], [])

    def test_retired_duplicate_is_history_not_a_second_body(self) -> None:
        rows = [
            _row(
                "embodiment:one",
                "incarnation:old",
                "cli:legion:body-a",
                status="retired",
            ),
            _row("embodiment:one", "incarnation:new", "cli:legion:body-a"),
        ]
        state = _runtime(
            self.root, "a", rows, origin=("embodiment:one", "incarnation:new")
        )
        code, report = _run(["--host", "legion", "--runtime", str(state)])
        self.assertEqual(code, 0)
        self.assertEqual(len(report["active"]), 1)
        self.assertEqual(len(report["retired"]), 1)
        self.assertEqual(report["retired"][0]["incarnation_id"], "incarnation:old")
        self.assertEqual(report["unservable"], [])

    def test_one_endpoint_shared_by_two_embodiments_is_a_collision(self) -> None:
        shared = "http://127.0.0.1:9/dm-peer/v1"
        rows = [
            _row("embodiment:one", "incarnation:one", "cli:legion:body-a"),
            _row("embodiment:two", "incarnation:two", "codex:legion:body-b"),
        ]
        first = _runtime(
            self.root,
            "a",
            rows,
            origin=("embodiment:one", "incarnation:one"),
            targets=[("embodiment:two", shared)],
        )
        second = _runtime(
            self.root,
            "b",
            rows,
            origin=("embodiment:two", "incarnation:two"),
            targets=[("embodiment:one", shared)],
        )
        code, report = _run(
            ["--host", "legion", "--runtime", str(first), "--runtime", str(second)]
        )
        self.assertEqual(code, 1)
        self.assertFalse(report["enrollable"])
        self.assertEqual(
            sorted(report["duplicate_endpoints"][shared]),
            ["embodiment:one", "embodiment:two"],
        )

    def test_same_pair_from_two_bundles_is_agreement_not_a_collision(self) -> None:
        rows = [
            _row("embodiment:one", "incarnation:one", "cli:legion:body-a"),
            _row("embodiment:two", "incarnation:two", "codex:legion:body-b"),
        ]
        peer = "http://127.0.0.1:9/dm-peer/v1"
        first = _runtime(
            self.root,
            "a",
            rows,
            origin=("embodiment:one", "incarnation:one"),
            targets=[("embodiment:two", peer)],
        )
        second = _runtime(
            self.root,
            "b",
            rows,
            origin=("embodiment:two", "incarnation:two"),
            targets=[("embodiment:two", peer)],
        )
        code, report = _run(
            ["--host", "legion", "--runtime", str(first), "--runtime", str(second)]
        )
        self.assertEqual(code, 0)
        self.assertEqual(report["duplicate_endpoints"], {})

    def test_probe_separates_serves_from_absent_and_from_inconclusive(self) -> None:
        """A 400 on the peer path proves a route; a 404 proves it is not there.

        A bare status code proves nothing on its own, which is why the two are
        probed against the same path. Anything that is not an answer at all stays
        inconclusive: mesh paths flap, and one failure must not be recorded as an
        absent route.
        """

        def handler(status: int) -> type[BaseHTTPRequestHandler]:
            class Handler(BaseHTTPRequestHandler):
                def do_POST(self) -> None:
                    size = int(self.headers.get("Content-Length") or 0)
                    self.rfile.read(size)
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, _format: str, *args: object) -> None:
                    return

            return Handler

        def serve(status: int) -> tuple[str, int]:
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler(status))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def cleanup() -> None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.addCleanup(cleanup)
            host, port = server.server_address[:2]
            return str(host), int(port)

        ok_host, ok_port = serve(400)
        missing_host, missing_port = serve(404)
        peer = preflight.PEER_PATH

        self.assertEqual(
            preflight.probe(f"http://{ok_host}:{ok_port}{peer}", 5.0), preflight.SERVES
        )
        self.assertEqual(
            preflight.probe(f"http://{missing_host}:{missing_port}{peer}", 5.0),
            preflight.ABSENT,
        )
        with socket.socket() as spare:
            spare.bind(("127.0.0.1", 0))
            closed_port = spare.getsockname()[1]
        # nothing listening: a refusal is not evidence that no route exists
        self.assertEqual(
            preflight.probe(f"http://127.0.0.1:{closed_port}{peer}", 1.0),
            preflight.INCONCLUSIVE,
        )
        # a URL that is not a peer endpoint is refused rather than probed
        self.assertEqual(
            preflight.probe(f"http://{ok_host}:{ok_port}/not-a-route", 1.0),
            preflight.INCONCLUSIVE,
        )
        self.assertEqual(
            preflight.probe("ftp://example.invalid/dm-peer/v1", 1.0),
            preflight.INCONCLUSIVE,
        )

    def test_only_runtime_json_is_read_and_no_custody_is_opened(self) -> None:
        rows = [_row("embodiment:one", "incarnation:one", "cli:legion:body-a")]
        state = _runtime(
            self.root,
            "a",
            rows,
            origin=("embodiment:one", "incarnation:one"),
            extra_files={
                "custody.json": b"canary-custody",
                "body.password": b"canary-password",
                "client.key": b"canary-key",
            },
        )
        read_paths: list[str] = []
        original = pathlib.Path.read_bytes

        def recording(self: pathlib.Path) -> bytes:
            read_paths.append(self.name)
            return original(self)

        with unittest.mock.patch.object(pathlib.Path, "read_bytes", recording):
            code, _report = _run(["--host", "legion", "--runtime", str(state)])
        self.assertEqual(code, 0)
        self.assertEqual(read_paths, ["runtime.json"])
        for forbidden in ("custody.json", "body.password", "client.key"):
            self.assertNotIn(forbidden, read_paths)


if __name__ == "__main__":
    unittest.main()
