"""Membership group integration over the existing authenticated HTTP transport."""

from __future__ import annotations

import threading
import unittest
import uuid
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import CommunicationStore
from daimon_matrix.daemon import create_messaging_http_server
from daimon_matrix.messaging import GroupMessaging, MessagingTribePolicy
from daimon_matrix.native_egress import (
    VISIBILITY_SCHEMA_VERSION,
    MandatoryEgressController,
    synthetic_visibility,
)
from daimon_matrix.routes import DirectHTTPProvider, OpaqueInbox, TransportIngress
from tests import test_dm051_sealed as sealing_fixtures


class GroupRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = sealing_fixtures.TribeConversationLaneTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        fixture = self.fixture
        root = Path(fixture.journey.root)
        self.groups = []
        self.servers = []
        for index, lane in enumerate((fixture.sender_lane, fixture.receiver_lane)):
            template = synthetic_visibility(clock=lane.clock)
            controller = MandatoryEgressController(
                policy=template._policy,
                proof_key=template._proof_key,
                transport=template._transport,
                clock=lane.clock,
                catalog_mode="migrate",
            )
            communication = CommunicationStore(
                lane.ledger,
                clock=lane.clock,
                foreign_authority_resolver=lane.authority_resolver,
            )
            communication.initialize()
            communication.upgrade_receipts_v2()
            communication.upgrade_legs_v3()
            group = GroupMessaging(
                lane=lane,
                policy=MessagingTribePolicy(
                    tribe_ref=fixture.tribe_ref,
                    membership_ref=fixture._membership_of(lane.being_ref),
                    classification="shareable",
                    max_ttl_ms=60_000,
                ),
                communication=communication,
                providers={},
                config_digest="0" * 64,
                egress=controller,
            )
            ingresses = {}
            origin_body = lane.ledger.local_origin["body_ref"]
            for phase in ("evidence", "message"):
                ingresses[phase] = TransportIngress(
                    provider_ref=f"body-{index}",
                    route_ref=f"body-{index}",
                    key_ref=f"key-{index}",
                    secret=bytes([index + 1]) * 32,
                    recipient_id=lane.local_embodiment_id,
                    recipient_body_ref=lane.ledger.local_origin["body_ref"],
                    recipient_embodiment_id=lane.local_embodiment_id,
                    inbox=OpaqueInbox(
                        root / f"{index}-{phase}.sqlite", clock=lane.clock
                    ),
                    clock=lane.clock,
                    egress=group.egress,
                    egress_catalog_id=f"{phase}-responses",
                    egress_authority_head=origin_body,
                    egress_authorizer=lambda binding, origin=origin_body: (
                        binding.authority_head == origin
                    ),
                    intake_validator=getattr(group, "receive_" + phase),
                    carrier_inspector=group.inspect_carrier,
                )
            server = create_messaging_http_server(
                ("127.0.0.1", 0),
                evidence_ingress=ingresses["evidence"],
                message_ingress=ingresses["message"],
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            self.groups.append(group)
            self.servers.append(server)
        for group in self.groups:
            for index, receiver in enumerate(self.groups):
                group.providers[
                    (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
                ] = {
                    phase: DirectHTTPProvider(
                        provider_ref=f"body-{index}",
                        route_ref=f"body-{index}",
                        key_ref=f"key-{index}",
                        secret=bytes([index + 1]) * 32,
                        route_class="direct",
                        sender_principal=group.lane.being_ref,
                        sender_body_ref=group.ledger.local_origin["body_ref"],
                        endpoint=f"http://127.0.0.1:{self.servers[index].server_port}"
                        f"/dm-messaging/v1/{phase}",
                        clock=group.lane.clock,
                        egress=group.egress,
                    )
                    for phase in ("evidence", "message")
                }

        for group in self.groups:
            group.egress.migrate_registered_catalogs(version=VISIBILITY_SCHEMA_VERSION)
            group.egress.validate_registered_catalogs()

    def test_real_http_intake_receipts_reply_and_exact_retry(self):
        sender, receiver = self.groups
        send_id, thread_id = str(uuid.uuid4()), str(uuid.uuid4())
        first = sender.send(
            client_id="test",
            send_id=send_id,
            thread_id=thread_id,
            text="one group message",
        )
        self.assertTrue(first["semantic"]["terminal"])
        items = receiver.page(after=0, limit=10)
        self.assertEqual(len(items), 1)
        self.assertEqual(
            items[0]["message"]["payload"]["body"]["text"], "one group message"
        )
        self.fixture.now += 1
        with patch.object(
            sender.lane, "snapshot", side_effect=AssertionError("resolved")
        ):
            retry = sender.send(
                client_id="test",
                send_id=send_id,
                thread_id=thread_id,
                text="one group message",
            )
        self.assertEqual(retry, first)
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        inspected = sender.inspect(client_id="test", send_id=send_id)
        self.assertEqual(inspected, first)
        reply = receiver.send(
            client_id="reply",
            send_id=str(uuid.uuid4()),
            thread_id=thread_id,
            text="connected reply",
            response_to=(receiver, first["message_id"]),
        )
        self.assertTrue(reply["semantic"]["terminal"])
        received = sender.page(after=0, limit=10)[0]["message"]
        self.assertEqual(
            received["payload"]["body"]["response_context"]["message_id"],
            first["message_id"],
        )
        # One visible speech obligation, irrespective of repeated HTTP copies.
        messages = [
            request
            for request in sender.egress._transport.requests
            if "one group message" in request["text"]
        ]
        self.assertEqual(len(messages), 1)
        sender.egress.validate_registered_catalogs()
        receiver.egress.validate_registered_catalogs()
        self.fixture.now += 60_000
        with patch.object(
            sender, "_transmit", side_effect=AssertionError("expired I/O")
        ):
            expired = sender.send(
                client_id="test",
                send_id=send_id,
                thread_id=thread_id,
                text="one group message",
            )
        self.assertTrue(expired["carrier"]["expired"])
        self.assertEqual(expired["semantic"], first["semantic"])
        self.assertEqual(sender.inspect(client_id="test", send_id=send_id), expired)

    def test_persistence_failure_cannot_sign_receipt(self):
        prepared = self.fixture.sender_lane.prepare(
            text="not stored",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.fixture.tribe_ref,
        )
        receiver = self.fixture.receiver_lane
        with (
            patch.object(receiver.records, "received", side_effect=OSError("disk")),
            patch.object(receiver, "_author_receipt") as author,
            self.assertRaises(OSError),
        ):
            receiver.intake(prepared["payload"])
        author.assert_not_called()

    def test_interrupted_visibility_admission_does_not_strand_native_carrier(self):
        sender = self.groups[0]
        request = {
            "client_id": "test",
            "send_id": str(uuid.uuid4()),
            "thread_id": str(uuid.uuid4()),
            "text": "recover the exact group operation",
        }
        with (
            patch.object(sender.egress, "admit_in_transaction", side_effect=OSError),
            self.assertRaises(OSError),
        ):
            sender.send(**request)
        self.assertIsNone(sender.records.get("native", request["send_id"]))
        sender.egress.validate_registered_catalogs()
        result = sender.send(**request)
        self.assertTrue(result["semantic"]["terminal"])
        sender.egress.validate_registered_catalogs()

    def test_restart_uses_byte_identical_frozen_envelope(self):
        lane = self.fixture.sender_lane
        params = dict(
            text="durable",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.fixture.tribe_ref,
        )
        original = lane.prepare(**params)
        restarted = self.fixture.lane_for(
            "founder",
            self.fixture.founder_ledger,
            self.fixture.sender_custody,
            self.fixture.journey.store,
        )
        self.fixture.now += 100
        with patch.object(
            restarted, "snapshot", side_effect=AssertionError("resolved")
        ):
            self.assertEqual(
                canonical_bytes(restarted.prepare(**params)), canonical_bytes(original)
            )

    def test_group_only_application_uses_supported_signed_provisioning(self):
        import hashlib

        from daimon_matrix.messaging_config import (
            APPLICATION_SCHEMA_V3,
            GROUP_STORE_NAMES,
            load_application,
            validate_shape,
        )
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.relationship_store import (
            RelationshipServiceContext,
            RelationshipStore,
        )
        from tests.test_messaging_runtime import loaded, public_document

        fixture = self.fixture
        _runtime_fixture, runtime, _reads = loaded(
            self, fixture.founder, clock=lambda: fixture.now
        )
        relationships = RelationshipStore(
            runtime.state_root / "relationships.sqlite",
            authority_resolver=fixture.sender_lane.authority_resolver,
        )
        for event in fixture.events:
            relationships.ingest(event)
        runtime.service.communication.upgrade_receipts_v2()
        runtime.service.communication.upgrade_legs_v3()
        runtime = replace(
            runtime,
            service=replace(
                runtime.service,
                relationships=RelationshipServiceContext(
                    relationships,
                    fixture.journey.card_verifier,
                    fixture.sender_lane.authority_resolver,
                ),
            ),
        )
        port = 48765
        sources, roster = {}, []
        directory = runtime.state_root.parent
        for index, identity in enumerate((fixture.founder, fixture.member)):
            path = directory / f"group-body-{index}.key"
            path.write_bytes(bytes([index + 1]) * 32)
            path.chmod(0o600)
            sources[path.name] = path
            roster.append(
                {
                    "being_ref": identity.state.being_ref,
                    "embodiment_id": identity.origin["embodiment_id"],
                    "body_ref": identity.origin["body_ref"],
                    "route": {
                        "provider_ref": f"body-{index}",
                        "route_ref": f"body-{index}",
                        "key_ref": f"body-{index}",
                        "endpoint": (
                            f"http://127.0.0.1:{port + index}/dm-messaging/v1/message"
                        ),
                        "secret_file": path.name,
                        "secret_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    },
                }
            )
        spec = {
            "schema": APPLICATION_SCHEMA_V3,
            "listen": {"host": "127.0.0.1", "port": port},
            "authorities": [
                public_document(fixture.founder, "founder"),
                public_document(fixture.member, "member"),
            ],
            "relationship_events": fixture.events,
            "relationship_mode": {
                "mode": "shared",
                "runtime_id": runtime.service.runtime_id,
                "state_root": str(runtime.state_root),
                "store_filename": relationships.path.name,
            },
            "tribe": {
                "channel_id": "tribe",
                "policy": {
                    "tribe_ref": fixture.tribe_ref,
                    "membership_ref": fixture.declaration["event_id"],
                    "classification": "shareable",
                    "max_ttl_ms": 60000,
                },
            },
            "intake": roster[0]["route"],
            "roster": roster,
            "stores": {name: name + ".sqlite" for name in GROUP_STORE_NAMES},
        }
        validate_shape(spec, specification=True)
        app = directory / "group-application"
        prepare(runtime, app, spec, secret_sources=sources)
        view = load_application(runtime, app)
        self.assertEqual(set(view.service.messaging.channels), {"tribe"})
        self.assertIsInstance(view.service.messaging.channels["tribe"], GroupMessaging)
        self.assertIs(
            view.service._messaging_context(startup=True), view.service.messaging
        )
        self.assertNotIn("incoming", spec)
        self.assertNotIn("outgoing", spec)
        import sqlite3

        group = view.service.messaging.channels["tribe"]
        request_id, moved_id = str(uuid.uuid4()), str(uuid.uuid4())
        document = {"client_id": "test", "text": "signed record"}
        group.records.reserve("request", request_id, document, lambda: document)
        with closing(sqlite3.connect(group.records.path)) as database, database:
            database.execute(
                "UPDATE tribe_records SET record_id=? WHERE record_id=?",
                (moved_id, request_id),
            )
        with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
            group.records.get("request", moved_id)


if __name__ == "__main__":
    unittest.main()
