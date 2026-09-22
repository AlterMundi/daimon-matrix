"""Three real disposable identities; no external host, Telegram or model calls."""

import copy
import hashlib
import secrets
import socket
import tempfile
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.chat_host import load_views, serve_views, validate_config
from daimon_matrix.client import ClientConfig, ClientError, LocalClient
from daimon_matrix.messaging_config import create_binding
from daimon_matrix.native_egress import SyntheticEchoTransport, closed_visibility
from daimon_matrix.runtime import load_runtime
from tools.chat_link import (
    disclosures,
    install_link,
    make_plan,
    now,
    read_public,
    sign_proposals,
)
from tools.prepare_chat_identity import prepare


class ChatHostTests(unittest.TestCase):
    def test_three_identities_preserve_first_link_and_capability_isolation(self):
        with tempfile.TemporaryDirectory(prefix="dm-host-") as directory:
            root = Path(directory).resolve()
            public, runtimes, passwords, configs = [], [], [], []
            for index in range(3):
                home = root / str(index)
                public.append(
                    read_public(
                        prepare(
                            home,
                            label=f"peer-{index}",
                            body_ref=f"cli:peer-{index}",
                            principal_id=f"peer-{index}",
                        )
                    )
                )
                passwords.append((home / "body.password").read_bytes())
                bundle_path = home / "package/runtime/runtime.json"
                bundle = read_public(bundle_path)
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    bundle["peer_transport"]["listen_port"] = reservation.getsockname()[
                        1
                    ]
                bundle_path.write_bytes(canonical_bytes(bundle))
                runtimes.append(
                    load_runtime(
                        home / "package/runtime",
                        "runtime.json",
                        lambda i=index: bytearray(passwords[i]),
                        clock=now,
                        egress=closed_visibility(clock=now, catalog_mode="migrate"),
                    )
                )
                configs.append(
                    {
                        "state_root": str(home / "package/runtime"),
                        "password_file": str(home / "body.password"),
                        "applications": [],
                    }
                )
            ports = []
            # Reserve distinct ports before closing sockets; no fixed CI ports.
            sockets = [socket.socket() for _ in range(4)]
            try:
                for sock in sockets:
                    sock.bind(("127.0.0.1", 0))
                    ports.append(sock.getsockname()[1])
            finally:
                for sock in sockets:
                    sock.close()
            for peer in (1, 2):
                # Reload the owner so the next enrollment sees retained cards.
                runtimes[0] = load_runtime(
                    Path(configs[0]["state_root"]),
                    "runtime.json",
                    lambda: bytearray(passwords[0]),
                    clock=now,
                    egress=closed_visibility(clock=now, catalog_mode="migrate"),
                )
                plan = make_plan(
                    runtimes[0],
                    public[0],
                    public[peer],
                    [f"http://127.0.0.1:{p}" for p in ports[(peer - 1) * 2 : peer * 2]],
                    {
                        "bot_id": 137,
                        "chat_id": -100137,
                        "topic_id": None,
                        "representation": "plain-json/v2",
                    },
                )
                if peer == 2:
                    self.assertFalse(
                        any(
                            e["kind"] == "matrix/relationship-card"
                            and e["being_ref"]
                            == public[0]["document"]["authority"]["manifest"][
                                "being_ref"
                            ]
                            for e in plan["events"]
                        )
                    )
                token = b"137:synthetic-unit-test-token"
                payload = {
                    "plan": plan,
                    "signed_events": sign_proposals(runtimes[peer], plan, 1),
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
                        "get_me_bot_id": 137,
                        "probe_chat_id": -100137,
                        "probe_topic_id": None,
                        "probe_message_id": 1,
                        "probe_text_sha256": "b" * 64,
                    },
                    "visibility_bindings": [
                        [create_binding(runtimes[i], d) for d in disclosures(plan)]
                        for i in (0, peer)
                    ],
                }
                for actor, index in enumerate((0, peer)):
                    output = root / f"link-{peer}-{index}"
                    output.mkdir(mode=0o700)
                    install_link(
                        Path(configs[index]["state_root"]),
                        passwords[index],
                        output,
                        payload,
                        actor,
                        additional_link=index == 0 and peer == 2,
                    )
                    configs[index]["applications"].append(
                        {
                            "directory": str(output / "application"),
                            "visibility": str(output / "visibility/installation.json"),
                            "socket": f"p{peer}.sock",
                        }
                    )
            validate_config({"schema": "dm.chat-host/v1", "runtimes": configs})
            views = [view for row in configs for view in load_views(row, clock=now)]
            self.assertIs(views[0].service.ledger, views[1].service.ledger)
            self.assertIsNot(views[0].egress, views[1].egress)
            self.assertNotEqual(
                views[0].service.runtime_id, views[3].service.runtime_id
            )
            # Loading and checking all links must not contact any peer or read inboxes.
            for view in views:
                view.service.messaging.channels["peer-in"].disclosure()
                view.service.messaging.deliveries[
                    "peer-out"
                ].sender.context.disclosure()
                view.egress._transport = SyntheticEchoTransport()
            stop = threading.Event()
            failures = []

            def run():
                try:
                    serve_views(views, stop)
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=run)
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while not all(v.socket_path.exists() for v in views):
                    if failures or time.monotonic() > deadline:
                        self.fail(str(failures))
                    time.sleep(0.05)

                def exercise_link(view_index):
                    row = configs[0]["applications"][view_index]
                    app = Path(row["directory"])
                    config = ClientConfig.load(
                        app / "client.json", (app / "client.key").read_bytes()
                    )
                    # A first-link capability cannot enter the other socket.
                    if view_index == 0:
                        wrong = LocalClient(views[1].socket_path, config)
                        with self.assertRaises(ClientError):
                            wrong.send(
                                wrong.prepare(
                                    "messaging.inbox",
                                    {"channel_id": "peer-in", "after": 0, "limit": 1},
                                )
                            )
                    delivery = views[view_index].service.messaging.deliveries[
                        "peer-out"
                    ]
                    send_id, thread_id = str(uuid.uuid4()), str(uuid.uuid4())
                    deadline = time.monotonic() + 20
                    while True:
                        result = delivery.send(
                            client_id=config.capability.client_id,
                            send_id=send_id,
                            thread_id=thread_id,
                            text=f"preserved-link-{view_index}",
                        )
                        if result["transport_status"] == "recipient-intake":
                            break
                        if time.monotonic() > deadline:
                            self.fail(str(result))
                        time.sleep(0.1)
                    incoming = (
                        views[view_index + 2]
                        .service.messaging.channels["peer-in"]
                        .page(after=0, limit=10)
                    )
                    self.assertEqual(len(incoming), 1)
                    self.assertEqual(
                        incoming[0]["message"]["payload"]["body"]["text"],
                        f"preserved-link-{view_index}",
                    )

                # Independent applications append through the same runtime's
                # canonical writer concurrently, without forks or lost messages.
                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(exercise_link, (0, 1)))
            finally:
                stop.set()
                thread.join(timeout=25)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertTrue(all(not v.socket_path.exists() for v in views))

    def test_configuration_rejects_duplicates_and_socket_traversal(self):
        value = {
            "schema": "dm.chat-host/v1",
            "runtimes": [
                {
                    "state_root": "/tmp/host-runtime",
                    "password_file": "/tmp/host-password",
                    "applications": [
                        {
                            "directory": "/tmp/host-app",
                            "visibility": "/tmp/host-visibility",
                            "socket": "matrix.sock",
                        }
                    ],
                }
            ],
        }
        validate_config(value)
        bad = copy.deepcopy(value)
        bad["runtimes"].append(copy.deepcopy(bad["runtimes"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate_runtime"):
            validate_config(bad)
        bad = copy.deepcopy(value)
        bad["runtimes"][0]["applications"][0]["socket"] = "../matrix.sock"
        with self.assertRaisesRegex(ValueError, "socket_invalid"):
            validate_config(bad)

    def test_one_failed_view_stops_and_joins_the_entire_host(self):
        from types import SimpleNamespace

        views = [
            SimpleNamespace(
                messaging_http=None,
                peer_dispatcher=None,
                socket_path=Path(f"/tmp/fake-{i}"),
            )
            for i in range(2)
        ]
        stop = threading.Event()
        with (
            patch("daimon_matrix.daemon.serve_forever", side_effect=ValueError("test")),
            self.assertRaisesRegex(ValueError, "link_failed"),
        ):
            serve_views(views, stop)
        self.assertTrue(stop.is_set())
