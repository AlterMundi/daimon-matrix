"""Trusted public relationship authorities need no foreign source Ledgers."""

import unittest

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.operator_rebirth import authority_from_document
from daimon_matrix.runtime import load_runtime
from tests.test_dm024_runtime import PASSWORD
from tests.test_messaging_runtime import application_fixture


def ordinary(test, runtime, spec, *, authorities=None):
    import json

    root = runtime.state_root
    bundle = json.loads((root / "runtime.json").read_bytes())
    bundle["relationships"] = {
        "store_filename": "ordinary-relationships.sqlite",
        "known_being_refs": [],
    }
    (root / "runtime.json").write_bytes(canonical_bytes(bundle))
    if authorities is None:
        authorities = {
            a.manifest.being_ref: a
            for a in map(authority_from_document, spec["authorities"])
        }
    return load_runtime(
        root,
        "runtime.json",
        lambda: bytearray(PASSWORD),
        clock=lambda: test.pair.now,
        relationship_authorities=authorities,
    )


def shared_fixture(test, *, ingest=True):
    runtime, spec, sources, _ = application_fixture(test)
    runtime = ordinary(test, runtime, spec)
    if ingest:
        for event in spec["relationship_events"]:
            runtime.service.relationships.store.ingest(event)
    spec["relationship_mode"] = {
        "mode": "shared",
        "runtime_id": runtime.service.runtime_id,
        "state_root": str(runtime.state_root),
        "store_filename": "ordinary-relationships.sqlite",
    }
    return runtime, spec, sources


class RuntimeRelationshipAuthorityTests(unittest.TestCase):
    def test_shared_prepare_reuses_ordinary_store_without_mutating_history(self):
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare

        runtime, spec, sources = shared_fixture(self)
        store = runtime.service.relationships.store
        before = store.path.read_bytes()
        target = self.root / "application"
        prepare(runtime, target, spec, secret_sources=sources)
        app = load_application(runtime, target)
        self.assertIs(app.service.relationships, runtime.service.relationships)
        self.assertIs(app.service.messaging.channels["peer-in"].relationships, store)
        self.assertIs(
            app.service.messaging.deliveries["peer-out"].sender.context.relationships,
            store,
        )
        self.assertEqual(before, store.path.read_bytes())
        self.assertFalse((target / spec["stores"]["relationships"]).exists())

    def test_authenticated_ordinary_revocation_blocks_send_read_cache_and_reload(self):
        from daimon_matrix.local_api import (
            create_request,
            request_hash,
            verify_response,
        )
        from daimon_matrix.messaging import MessagingChannel, MessagingSender
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.messaging_store import MessagingOutboxStore
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.synthetic_relationships import _uuid
        from tests.test_native_messaging import NOW

        runtime, spec, sources = shared_fixture(self)
        target = self.root / "app"
        receipt = prepare(runtime, target, spec, secret_sources=sources)
        app = load_application(runtime, target)
        channel = app.service.messaging.channels["peer-in"]
        # Independently signed member -> founder encrypted message, not a fake row.
        reverse = MessagingChannel(
            policy=channel.policy,
            local_being_ref=channel.local_being_ref,
            local_credential_id=channel.local_credential_id,
            authority_resolver=channel.authority_resolver,
            relationships=self.pair.receiver_relationships,
            custody=self.pair.receiver_custody,
            inbox=self.pair.receiver.inbox,
            clock=lambda: self.pair.now,
        )
        sender = MessagingSender(
            context=reverse,
            ledger=self.pair.local_ledger,
            signer=self.pair.recipient.signer,
            custody=self.pair.receiver_custody,
            outbox=MessagingOutboxStore(self.root / "reverse-outbox.sqlite"),
            clock=lambda: self.pair.now,
        )
        evidence, message = sender.prepare(
            client_id="client:reverse",
            send_id=_uuid("shared-reverse-send"),
            thread_id=_uuid("shared-thread"),
            text="actual shared inbox plaintext",
        )
        channel.receive_evidence(evidence)
        channel.receive_message(message)
        cap = app.service.capabilities[receipt["capability_id"]]

        def request(capability, method, params, label):
            return create_request(
                capability,
                request_id=_uuid(label),
                issued_at_ms=self.pair.now,
                method=method,
                params=params,
            )

        def invoke(capability, req):
            return verify_response(
                app.service.handle(req),
                capability,
                expected_request_id=req["request_id"],
                expected_request_hash=request_hash(req),
                expected_server=app.service.origin,
                expected_runtime=app.service.runtime_identity,
            )

        cached = request(
            cap,
            "messaging.inbox",
            {"channel_id": "peer-in", "after": 0, "limit": 10},
            "shared-read",
        )
        self.assertTrue(invoke(cap, cached)["ok"])
        self.assertTrue(invoke(cap, cached)["ok"])
        self.assertEqual(len(channel.page(after=0, limit=10)), 1)
        ingest_cap = next(
            c
            for c in app.service.capabilities.values()
            if "relationship.event.ingest" in c.methods
        )
        revoked = next(
            e
            for e in self.pair.history
            if e["kind"] == "matrix/relationship-grant-revocation"
        )
        self.pair.now = NOW + 17
        ingestion = request(
            ingest_cap, "relationship.event.ingest", {"event": revoked}, "shared-revoke"
        )
        self.assertTrue(invoke(ingest_cap, ingestion)["ok"])
        self.assertIn(revoked, runtime.service.relationships.store.events())
        before = runtime.service.relationships.store.path.read_bytes()
        for req in (
            cached,
            request(
                cap,
                "messaging.inbox",
                {"channel_id": "peer-in", "after": 0, "limit": 10},
                "shared-fresh-read",
            ),
            request(
                cap,
                "messaging.send",
                {
                    "channel_id": "peer-out",
                    "send_id": _uuid("shared-fresh-send"),
                    "thread_id": _uuid("shared-thread"),
                    "text": "must not leave",
                },
                "shared-send",
            ),
        ):
            result = invoke(cap, req)
            self.assertFalse(result["ok"], result)
            self.assertIsNone(result["result"])
        with self.assertRaises(ValueError):
            channel.page(after=0, limit=10)
        with self.assertRaises(ValueError):
            channel.receive_message(message)
        runtime = ordinary(self, runtime, spec)
        with self.assertRaises(ValueError):
            load_application(runtime, target)
        self.assertEqual(before, runtime.service.relationships.store.path.read_bytes())

    def test_shared_prepare_requires_preingested_history(self):
        from daimon_matrix.operator_messaging import prepare

        runtime, spec, sources = shared_fixture(self, ingest=False)
        store = runtime.service.relationships.store
        before = store.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "messaging_shared_history_incomplete"):
            prepare(runtime, self.root / "app", spec, secret_sources=sources)
        self.assertEqual(before, store.path.read_bytes())
        self.assertFalse((self.root / "app").exists())

    def test_shared_signed_selection_and_authority_mismatches_reject(self):
        import copy

        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.synthetic_relationships import _identity

        runtime, spec, sources = shared_fixture(self)
        before = runtime.service.relationships.store.path.read_bytes()
        for field in ("runtime_id", "state_root", "store_filename", "mode"):
            changed = copy.deepcopy(spec)
            changed["relationship_mode"][field] = "wrong"
            with self.subTest(field=field), self.assertRaises(ValueError):
                prepare(runtime, self.root / field, changed, secret_sources=sources)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        # Merely passing a different trusted context never changes signed selection.
        from dataclasses import replace

        context = runtime.service.relationships
        changed = replace(
            context, authority_resolver=lambda ref: _identity("delegate").authority
        )
        with self.assertRaisesRegex(
            ValueError, "messaging_relationship_authority_mismatch"
        ):
            load_application(
                replace(
                    runtime, service=replace(runtime.service, relationships=changed)
                ),
                target,
            )
        changed = replace(context, authority_resolver=lambda ref: {}[ref])
        with self.assertRaises(ValueError):
            load_application(
                replace(
                    runtime, service=replace(runtime.service, relationships=changed)
                ),
                target,
            )
        self.assertEqual(before, context.store.path.read_bytes())

    def test_authority_seam_requires_explicit_ordinary_configuration(self):
        from daimon_matrix.runtime import RuntimeError

        runtime, spec, _, _ = application_fixture(self)
        public = {
            a.manifest.being_ref: a
            for a in map(authority_from_document, spec["authorities"])
        }
        with self.assertRaisesRegex(
            RuntimeError, "runtime_relationship_configuration_rejected"
        ):
            load_runtime(
                runtime.state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: self.pair.now,
                relationship_authorities=public,
            )

    def test_historical_event_authority_is_not_current_card_authority(self):
        import copy

        from daimon_matrix.authority_epochs import (
            RootHistoryAuthority,
            create_authority_epoch,
        )
        from daimon_matrix.identity import create_incarnation_authorization
        from daimon_matrix.relationships import RelationshipError
        from daimon_matrix.weave import BeingManifest, RootAuthority

        runtime, spec, _, _ = application_fixture(self)
        member = self.pair.recipient
        old = member.authority
        auth = create_incarnation_authorization(
            member.credential,
            member.signer.seed,
            incarnation_id="incarnation:shared-successor",
            incarnation_sequence=1,
            started_at_ms=self.pair.now,
        )
        rows = copy.deepcopy(old.manifest.value["embodiments"])
        row = rows[0]
        row["status"] = "retired"
        rows.append(
            {
                **row,
                "status": "active",
                "incarnation_id": auth["body"]["incarnation_id"],
                "incarnation_authorization_id": auth["artifact_id"],
            }
        )
        rows.sort(key=lambda r: (r["embodiment_id"], r["incarnation_id"]))
        manifest = BeingManifest.from_value(
            {
                **old.manifest.value,
                "revision": old.manifest.value["revision"] + 1,
                "embodiments": rows,
            }
        )
        active = RootAuthority(
            manifest,
            old.state,
            old.credentials,
            {**old.incarnations, auth["artifact_id"]: auth},
        )
        transition = create_authority_epoch(
            old.manifest,
            manifest,
            embodiment_id=member.origin["embodiment_id"],
            previous_incarnation_id=member.origin["incarnation_id"],
            successor_authorization=auth,
            signing_seed=member.signer.seed,
            issued_at_ms=self.pair.now,
        )
        history = RootHistoryAuthority(active, [old], [transition])
        public = {
            a.manifest.being_ref: a
            for a in map(authority_from_document, spec["authorities"])
        }
        public[member.state.being_ref] = history
        runtime = ordinary(self, runtime, spec, authorities=public)
        context = runtime.service.relationships
        card = next(
            e
            for e in spec["relationship_events"]
            if e["kind"] == "matrix/relationship-card"
            and e["being_ref"] == member.state.being_ref
        )
        context.store.ingest(card)
        self.assertEqual(context.store.events(), [card])
        self.assertEqual(context.authority_resolver(member.state.being_ref), active)
        with self.assertRaises(RelationshipError):
            context.card_verifier(card["payload"], self.pair.now)

    def test_unknown_peer_and_local_authority_mismatch_reject(self):
        from daimon_matrix.relationship_store import RelationshipStoreError
        from daimon_matrix.runtime import RuntimeError

        runtime, spec, _, _ = application_fixture(self)
        local = runtime.service.ledger.authority
        runtime = ordinary(
            self, runtime, spec, authorities={local.manifest.being_ref: local}
        )
        foreign = next(
            e
            for e in spec["relationship_events"]
            if e["being_ref"] != local.manifest.being_ref
        )
        before = runtime.service.relationships.store.path.read_bytes()
        with self.assertRaises(RelationshipStoreError):
            runtime.service.relationships.store.ingest(foreign)
        self.assertEqual(before, runtime.service.relationships.store.path.read_bytes())
        peer = self.pair.recipient.authority
        with self.assertRaisesRegex(
            RuntimeError, "runtime_relationship_authority_inventory_mismatch"
        ):
            ordinary(self, runtime, spec, authorities={local.manifest.being_ref: peer})

    def test_host_can_preload_signed_public_authorities_before_base_runtime(self):
        import copy

        from daimon_matrix import messaging_config as config
        from daimon_matrix.operator_messaging import prepare

        runtime, spec, sources = shared_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        from unittest.mock import patch

        with patch(
            "daimon_matrix.keystore.EncryptedKeystore.open",
            side_effect=AssertionError("public preflight must not open custody"),
        ):
            public = config.read_application_authorities(
                runtime.state_root, "runtime.json", target, at_ms=self.pair.now
            )
        self.assertNotIn(runtime.service.ledger.authority.manifest.being_ref, public)
        fresh = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            relationship_authorities=public,
        )
        app = config.load_application(fresh, target)
        self.assertTrue(
            app.service.messaging.channels["peer-in"].disclosure()["authorized"]
        )
        self.assertEqual(
            app.service.relationships.store.path,
            runtime.service.relationships.store.path,
        )
        original = (target / "application.json").read_bytes()
        import json

        changed = copy.deepcopy(json.loads(original))
        changed["authorities"].pop()
        (target / "application.json").write_bytes(canonical_bytes(changed))
        with self.assertRaises(ValueError):
            config.read_application_authorities(
                runtime.state_root, "runtime.json", target, at_ms=self.pair.now
            )

    def test_binding_expired_public_identity_retains_bounded_error(self):
        from dataclasses import replace

        from daimon_matrix.messaging_config import create_binding, verify_binding

        runtime, _, _, _ = application_fixture(self)
        value = {"public": "binding"}
        binding = create_binding(runtime, value)
        expired = replace(
            runtime, service=replace(runtime.service, clock=lambda: 2**53)
        )
        with self.assertRaisesRegex(ValueError, "^messaging_binding_rejected$"):
            verify_binding(expired, value, binding)

    def test_prebase_preflight_rejects_damaged_shared_store_without_repair(self):
        import sqlite3
        from contextlib import closing

        from daimon_matrix.messaging_config import read_application_authorities
        from daimon_matrix.operator_messaging import prepare

        runtime, spec, sources = shared_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        path = runtime.service.relationships.store.path
        with closing(sqlite3.connect(path)) as db:
            db.execute("DROP TABLE operations")
            db.commit()
        before = path.read_bytes()
        with self.assertRaisesRegex(ValueError, "messaging_required_store_invalid"):
            read_application_authorities(
                runtime.state_root, "runtime.json", target, at_ms=self.pair.now
            )
        self.assertEqual(before, path.read_bytes())

    def test_channel_history_ingest_visible_to_ordinary_context(self):
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare
        from tests.test_native_messaging import NOW

        runtime, spec, sources = shared_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        app = load_application(runtime, target)
        channel = app.service.messaging.channels["peer-in"]
        revoked = next(
            e
            for e in self.pair.history
            if e["kind"] == "matrix/relationship-grant-revocation"
        )
        channel.relationships.ingest(revoked)
        self.pair.now = NOW + 17
        context = runtime.service.relationships
        self.assertIn(revoked, context.store.events())
        report = context.store.view(
            at_ms=self.pair.now, card_verifier=context.card_verifier
        ).report()
        self.assertEqual(report["grants"][revoked["payload"]["grant_id"]], "revoked")

    def test_public_authorities_ingest_without_foreign_ledger(self):
        from unittest.mock import patch

        from daimon_matrix.ledger import Ledger

        runtime, spec, _, _ = application_fixture(self)
        with patch("daimon_matrix.runtime.Ledger", wraps=Ledger) as ledgers:
            shared = ordinary(self, runtime, spec)
        self.assertEqual(ledgers.call_count, 1)
        for event in spec["relationship_events"]:
            shared.service.relationships.store.ingest(event)
        self.assertEqual(
            shared.service.relationships.store.events(), spec["relationship_events"]
        )
        self.assertIsNotNone(shared.service.relationships.authority_resolver)
