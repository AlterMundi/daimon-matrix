"""Owner-local application binding tests; no live enrollment."""

import copy
import unittest
from pathlib import Path

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.runtime import load_runtime
from tests.test_dm022_ledger import seed
from tests.test_dm024_runtime import NOW, PASSWORD, RuntimeFixture


def loaded(test, identity=None):
    fixture = RuntimeFixture()
    fixture.setUp()
    test.addCleanup(fixture.tearDown)
    root, bundle, _ = fixture.make_bundle(
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
    if identity is not None:
        from daimon_matrix.keystore import EncryptedKeystore
        from daimon_matrix.operator_capabilities import (
            create_operator_capability_binding,
            operator_runtime_id,
        )
        from daimon_matrix.synthetic_relationships import _seed

        original = EncryptedKeystore(root / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        secrets = dict(original.secrets)
        secrets["runtime.signing.v1:local"] = identity.signer.seed
        secrets["peer.encryption.v1:local"] = _seed("founder:encryption")
        (root / "custody.json").unlink()
        EncryptedKeystore.create(
            root / "custody.json",
            lambda: bytearray(PASSWORD),
            control_head=identity.state.head,
            secrets=secrets,
        )
        bundle.update(
            control_artifacts=public_document(identity, "founder")["control_artifacts"],
            control_head=identity.state.head,
            manifest=identity.authority.manifest.value,
            credentials=list(identity.authority.credentials.values()),
            incarnations=list(identity.authority.incarnations.values()),
            local_origin=identity.origin,
        )
        bundle["runtime_id"] = operator_runtime_id(
            "local", identity.state.being_ref, identity.origin, identity.signer.key_id
        )
        for row in bundle["capabilities"]:
            row["runtime_id"] = bundle["runtime_id"]
        bundle["operator_capability_binding"] = create_operator_capability_binding(
            runtime_id=bundle["runtime_id"],
            runtime_label="local",
            being_ref=identity.state.being_ref,
            origin=identity.origin,
            signing_seed=identity.signer.seed,
            capability_rows=bundle["capabilities"],
        )
        for path in root.glob("**/client.json"):
            client = __import__("json").loads(path.read_bytes())
            client.update(
                runtime_id=bundle["runtime_id"], expected_server=identity.origin
            )
            path.write_bytes(canonical_bytes(client))
        bundle["peer_transport"]["targets"] = []
    (root / "runtime.json").write_bytes(canonical_bytes(bundle))
    reads = []

    def password():
        reads.append(True)
        test.assertEqual(len(reads), 1)
        return bytearray(PASSWORD)

    runtime = load_runtime(root, "runtime.json", password, clock=lambda: NOW)
    return fixture, runtime, reads


class BindingTests(unittest.TestCase):
    def test_exact_binding_current_runtime_and_signature_domain(self):
        import daimon_matrix.messaging_config as config

        _fixture, runtime, reads = loaded(self)
        document = {"a": "exact public application"}
        before = (runtime.state_root / "custody.json").read_bytes()
        binding = config.create_binding(runtime, document)
        config.verify_binding(runtime, document, binding)
        self.assertEqual(reads, [True])
        self.assertEqual(before, (runtime.state_root / "custody.json").read_bytes())
        for changed in ({"a": "changed"}, {"a": document["a"], "extra": True}):
            with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
                config.verify_binding(runtime, changed, binding)
        for field in ("runtime_id", "control_head", "manifest_hash", "signing_key_id"):
            altered = copy.deepcopy(binding)
            altered["body"][field] = "wrong"
            with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
                config.verify_binding(runtime, document, altered)
        altered = copy.deepcopy(binding)
        altered["extra"] = True
        with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
            config.verify_binding(runtime, document, altered)
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from daimon_matrix.canonical import unb64url

        with self.assertRaises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(
                runtime.service.signer.public_key
            ).verify(
                unb64url(binding["signature"], length=64),
                canonical_bytes(binding["body"]),
            )


def public_document(identity, label):
    from daimon_matrix.identity import create_synthetic_genesis_in_process
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA
    from daimon_matrix.synthetic_relationships import _seed

    genesis = create_synthetic_genesis_in_process(
        tuple(_seed(f"{label}:root:{i}") for i in range(3)),
        2,
        tuple(_seed(f"{label}:recovery:{i}") for i in range(3)),
        2,
        created_at_ms=0,
        nonce=_seed(f"{label}:being"),
    )
    return {
        "schema": AUTHORITY_SCHEMA,
        "control_artifacts": [genesis],
        "control_head": identity.state.head,
        "manifest": identity.authority.manifest.value,
        "credentials": list(identity.authority.credentials.values()),
        "incarnations": list(identity.authority.incarnations.values()),
    }


def application_fixture(test):
    import tempfile
    from dataclasses import asdict

    from daimon_matrix.synthetic_relationships import _identity
    from tests.test_native_messaging import NativeSendRpcTests, Pair

    temporary = tempfile.TemporaryDirectory()
    test.addCleanup(temporary.cleanup)
    test.root = Path(temporary.name)
    pair = Pair(test.root)
    test.pair = pair
    reverse = NativeSendRpcTests.reverse_channel(test, pair)
    _fixture, runtime, reads = loaded(test, pair.sender)
    # Signed relationship events are at the synthetic relationship clock.
    from dataclasses import replace

    runtime = replace(runtime, service=replace(runtime.service, clock=lambda: pair.now))
    routes = {}
    sources = {}
    for direction in ("incoming", "outgoing"):
        routes[direction] = {}
        for phase in ("evidence", "message"):
            name = f"{direction}-{phase}.key"
            key = seed(name)
            path = test.root / name
            path.write_bytes(key)
            path.chmod(0o600)
            sources[name] = path
            routes[direction][phase] = {
                "provider_ref": f"provider:{phase}",
                "route_ref": f"route:{phase}",
                "key_ref": f"key:{direction}:{phase}",
                "secret_file": name,
                "secret_sha256": __import__("hashlib").sha256(key).hexdigest(),
                "endpoint": f"http://127.0.0.1:45200/dm-messaging/v1/{phase}",
            }
    spec = {
        "schema": "dm.messaging.application/v1",
        "listen": {"host": "127.0.0.1", "port": 45200},
        "authorities": [
            public_document(_identity(label), label)
            for label in ("founder", "member", "delegate")
        ],
        "relationship_events": pair.sender_relationships.events(),
        "incoming": {
            "channel_id": "peer-in",
            "recipient_being_ref": pair.sender.state.being_ref,
            "recipient_credential_id": pair.sender.credential["artifact_id"],
            "policy": asdict(reverse.policy),
            "routes": routes["incoming"],
        },
        "outgoing": {
            "channel_id": "peer-out",
            "recipient_being_ref": pair.recipient.state.being_ref,
            "recipient_credential_id": pair.recipient.credential["artifact_id"],
            "policy": asdict(pair.policy),
            "routes": routes["outgoing"],
        },
        "stores": {
            name: name + ".sqlite"
            for name in (
                "relationships",
                "inbox",
                "outgoing-context",
                "outbox",
                "opaque-evidence",
                "opaque-message",
            )
        },
    }
    spec = __import__("json").loads(canonical_bytes(spec))
    return runtime, spec, sources, reads


class ComposeTests(unittest.TestCase):
    def test_prepare_load_v7_one_shot_and_bounded_client(self):
        from daimon_matrix.messaging_config import config_digest, load_application
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.service import MESSAGING_METHODS

        runtime, spec, sources, reads = application_fixture(self)
        original = (runtime.state_root / "runtime.json").read_bytes()
        target = self.root / "application"
        result = prepare(runtime, target, spec, secret_sources=sources)
        composed = load_application(runtime, target)
        self.assertEqual(result["status"], "configured")
        self.assertEqual(composed.messaging_http.listen, ("127.0.0.1", 45200))
        self.assertEqual(set(composed.service.messaging.channels), {"peer-in"})
        self.assertEqual(set(composed.service.messaging.deliveries), {"peer-out"})
        self.assertEqual(
            set(composed.service.capabilities) - set(runtime.service.capabilities),
            {result["capability_id"]},
        )
        cap = composed.service.capabilities[result["capability_id"]]
        self.assertEqual(set(cap.methods), MESSAGING_METHODS)
        self.assertEqual(reads, [True])
        self.assertEqual(original, (runtime.state_root / "runtime.json").read_bytes())
        app = __import__("json").loads((target / "application.json").read_bytes())
        delivery = composed.service.messaging.deliveries["peer-out"]
        self.assertEqual(
            delivery.config_digest,
            config_digest({k: v for k, v in app.items() if k != "client"}),
        )
        self.assertEqual(
            composed.service.messaging.channels["peer-in"].disclosure()["authorized"],
            True,
        )

    def test_manual_reads_survive_transport_expiry_with_current_grants(self):
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.synthetic_relationships import _uuid

        runtime, spec, sources, _ = application_fixture(self)
        # Isolate transport expiry from this fixture's independently short grants.
        spec["outgoing"]["policy"]["max_ttl_ms"] = 1
        target = self.root / "ttl-app"
        result = prepare(runtime, target, spec, secret_sources=sources)
        application = load_application(runtime, target)
        sender = application.service.messaging.deliveries["peer-out"].sender
        cap = application.service.capabilities[result["capability_id"]]
        evidence, message = sender.prepare(
            client_id=cap.client_id,
            send_id=_uuid("ttl-send"),
            thread_id=_uuid("ttl-thread"),
            text="retained",
        )
        from dataclasses import replace

        self.pair.receiver.policy = replace(self.pair.receiver.policy, max_ttl_ms=1)
        self.pair.receiver.receive_evidence(evidence)
        self.pair.receiver.receive_message(message)
        self.pair.now += 2
        self.assertTrue(self.pair.receiver.disclosure()["authorized"])
        with self.assertRaises(ValueError):
            self.pair.receiver.receive_evidence(evidence)
        rows = self.pair.receiver.page(after=0, limit=1)
        self.assertEqual(rows[0]["message"]["payload"]["body"]["text"], "retained")
        self.assertEqual(
            self.pair.receiver.message(rows[0]["message"]["event_id"]),
            rows[0]["message"],
        )

    def test_public_schemas_match_runtime_shapes(self):
        import json

        from jsonschema import Draft202012Validator

        from daimon_matrix.messaging_config import (
            APPLICATION_JSON_SCHEMA,
            BINDING_JSON_SCHEMA,
        )

        root = Path(__file__).resolve().parents[1] / "schemas/messaging/v1"
        for name, expected in (
            ("application", APPLICATION_JSON_SCHEMA),
            ("operator-binding", BINDING_JSON_SCHEMA),
        ):
            value = json.loads((root / (name + ".schema.json")).read_bytes())
            Draft202012Validator.check_schema(value)
            self.assertEqual(value, expected)
        runtime, spec, sources, _ = application_fixture(self)
        from daimon_matrix.operator_messaging import prepare

        target = self.root / "schema-application"
        prepare(runtime, target, spec, secret_sources=sources)
        for filename, schema in (
            ("application.json", APPLICATION_JSON_SCHEMA),
            ("binding.json", BINDING_JSON_SCHEMA),
        ):
            document = json.loads((target / filename).read_bytes())
            Draft202012Validator(schema).validate(document)
            document["extra"] = True
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(document)))

    def test_configured_outgoing_delivery_reaches_real_http_recipient(self):
        import threading

        from daimon_matrix.daemon import create_messaging_http_server
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.routes import OpaqueInbox, TransportIngress
        from daimon_matrix.synthetic_relationships import _uuid

        runtime, spec, sources, _ = application_fixture(self)
        peer = self.pair.recipient
        ingresses = {}
        for phase in ("evidence", "message"):
            route = spec["outgoing"]["routes"][phase]
            ingresses[phase] = TransportIngress(
                **{k: route[k] for k in ("provider_ref", "route_ref", "key_ref")},
                secret=sources[route["secret_file"]].read_bytes(),
                recipient_id=spec["outgoing"]["policy"]["membership_ref"],
                recipient_body_ref=peer.origin["body_ref"],
                recipient_embodiment_id=peer.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / ("http-" + phase + ".sqlite"),
                    clock=runtime.service.clock,
                ),
                clock=runtime.service.clock,
                intake_validator=getattr(self.pair.receiver, "receive_" + phase),
            )
        server = create_messaging_http_server(
            ("127.0.0.1", 0),
            evidence_ingress=ingresses["evidence"],
            message_ingress=ingresses["message"],
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            for phase in ("evidence", "message"):
                spec["outgoing"]["routes"][phase]["endpoint"] = (
                    f"http://127.0.0.1:{server.server_port}/dm-messaging/v1/{phase}"
                )
            target = self.root / "http-application"
            result = prepare(runtime, target, spec, secret_sources=sources)
            composed = load_application(runtime, target)
            cap = composed.service.capabilities[result["capability_id"]]
            delivery = composed.service.messaging.deliveries["peer-out"]
            receipt = delivery.send(
                client_id=cap.client_id,
                send_id=_uuid("configured-send"),
                thread_id=_uuid("configured-thread"),
                text="configured HTTP delivery",
            )
            self.assertEqual(
                self.pair.receiver.page(after=0, limit=1)[0]["message"]["payload"][
                    "body"
                ]["text"],
                "configured HTTP delivery",
            )
            self.assertFalse(receipt["ambiguous"])
            self.assertEqual(receipt["transport_status"], "recipient-intake")
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
