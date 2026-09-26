from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
)
from daimon_matrix.identity import (
    create_embodiment_credential,
    create_incarnation_authorization,
    create_revocation,
    encryption_descriptor,
    signing_descriptor,
    verify_successor,
    x25519_public,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.ledger import Ledger
from daimon_matrix.sealed import (
    MEMBERSHIP_PROOF_SCHEMA,
    DisclosureAuthorization,
    EnvelopeStore,
    KeystoreDeliveryCustody,
    RecipientTarget,
    SealedDeliveryConflict,
    SealedDeliveryError,
    _parse,
    open_event,
    recipient_descriptor,
    seal_event,
    sealing_plan_hash,
    sender_descriptor,
)
from daimon_matrix.synthetic_relationships import _Journey
from daimon_matrix.tribe_conversation import (
    ACCEPTANCE_KIND,
    DECLARATION_KIND,
    TRIBE_CONVERSE_RESULT_SCHEMA,
    MembershipAuthorizer,
    TribeConversation,
    TribeConversationError,
)
from daimon_matrix.weave import BeingManifest, RootAuthority, create_event
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b"dm051-test-only-password"


class SealedFixture(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.targets: dict[str, RecipientTarget] = {}
        self.custodies: dict[str, KeystoreDeliveryCustody] = {}
        self.keystores: dict[str, EncryptedKeystore] = {}
        for label in ("legion", "daimonmatrix"):
            credential = next(
                value
                for value in self.credentials.values()
                if value["body"]["embodiment_id"] == f"embodiment:{label}"
            )
            target = RecipientTarget(self.authority, credential["artifact_id"])
            self.targets[label] = target
            directory = self.root_path / f"custody-{label}"
            directory.mkdir(mode=0o700)
            signing_id = signing_descriptor(self.signing_seeds[label])["key_id"]
            encryption_id = encryption_descriptor(seed(f"{label}-encryption"))["key_id"]
            signing_slot = f"sealed.signing.v1:{label}"
            encryption_slot = f"sealed.encryption.v1:{label}"
            store = EncryptedKeystore.create(
                directory / "keys.json",
                lambda: bytearray(PASSWORD),
                control_head=self.state.head,
                secrets={
                    signing_slot: self.signing_seeds[label],
                    encryption_slot: seed(f"{label}-encryption"),
                },
            )
            self.keystores[label] = store
            self.custodies[label] = KeystoreDeliveryCustody(
                store,
                lambda: bytearray(PASSWORD),
                control_head=self.state.head,
                counter=1,
                signing_slots={signing_id: signing_slot},
                encryption_slots={encryption_id: encryption_slot},
            )

    def material(
        self, labels: tuple[str, ...] = ("legion", "daimonmatrix")
    ) -> tuple[dict[str, object], list[RecipientTarget], DisclosureAuthorization]:
        event = self.append(self.ledger_a, "legion", "encrypted hello")
        targets = [self.targets[label] for label in labels]
        sender = sender_descriptor(event, self.authority, at_ms=NOW)
        recipients = sorted(
            (recipient_descriptor(target, at_ms=NOW) for target in targets),
            key=lambda row: (
                row["being_ref"],
                row["embodiment_id"],
                row["encryption_kid"],
            ),
        )
        authorization = DisclosureAuthorization.synthetic(
            event=event,
            sender=sender,
            recipients=recipients,
            evidence_hash=hashlib.sha256(
                b"verified synthetic DM-054 evidence"
            ).hexdigest(),
            authorized_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            authorization_id="00000000-0000-4000-8000-000000000051",
        )
        return event, targets, authorization

    def envelope(
        self, labels: tuple[str, ...] = ("legion", "daimonmatrix")
    ) -> tuple[
        dict[str, object], list[RecipientTarget], DisclosureAuthorization, bytes
    ]:
        event, targets, authorization = self.material(labels)
        raw = seal_event(
            event,
            sender_authority=self.authority,
            recipients=targets,
            authorization=authorization,
            custody=self.custodies["legion"],
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
        )
        return event, targets, authorization, raw


class RecipientEncryptionTests(SealedFixture):
    def test_two_recipients_independently_open_same_canonical_event(self) -> None:
        event, _, authorization, raw = self.envelope()
        document = json.loads(raw)
        schema = json.loads(
            (ROOT / "schemas/communication/v1/sealed-delivery.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
        auth_schema = json.loads(
            (
                ROOT
                / "schemas/communication/v1/disclosure-authorization-input.schema.json"
            ).read_bytes()
        )
        Draft202012Validator(auth_schema, format_checker=FormatChecker()).validate(
            authorization.value
        )

        for label in ("legion", "daimonmatrix"):
            opened = open_event(
                raw,
                sender_authority=self.authority,
                local_target=self.targets[label],
                recipient_targets=[
                    self.targets["legion"],
                    self.targets["daimonmatrix"],
                ],
                authorization=authorization,
                custody=self.custodies[label],
                at_ms=NOW + 1,
            )
            self.assertEqual(canonical_bytes(opened), canonical_bytes(event))
        self.assertNotIn(b"encrypted hello", raw)

    def test_direct_recipient_and_nonrecipient_have_one_stable_failure(self) -> None:
        _, _, authorization, raw = self.envelope(("legion",))
        with self.assertRaisesRegex(SealedDeliveryError, "sealed_delivery_rejected"):
            open_event(
                raw,
                sender_authority=self.authority,
                local_target=self.targets["daimonmatrix"],
                recipient_targets=[self.targets["legion"]],
                authorization=authorization,
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 1,
            )

    def test_reseal_keeps_event_but_refreshes_every_delivery_secret(self) -> None:
        event, targets, authorization = self.material()
        raws = [
            seal_event(
                event,
                sender_authority=self.authority,
                recipients=targets,
                authorization=authorization,
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 30_000,
            )
            for _ in range(24)
        ]
        documents = [json.loads(raw) for raw in raws]
        self.assertEqual(len(set(raws)), len(raws))
        self.assertEqual(len({row["delivery_id"] for row in documents}), len(raws))
        self.assertEqual(len({row["payload"]["nonce"] for row in documents}), len(raws))
        self.assertEqual(
            len(
                {tuple(item["enc"] for item in row["recipients"]) for row in documents}
            ),
            len(raws),
        )
        self.assertEqual({row["event_id"] for row in documents}, {event["event_id"]})

    def test_tampering_and_noncanonical_inputs_fail_before_plaintext(self) -> None:
        _, _, authorization, raw = self.envelope()
        original = json.loads(raw)
        mutations = []
        for path, replacement in (
            (("profile",), "downgrade"),
            (("event_hash",), "0" * 64),
            (("sensitivity",), "shareable"),
            (("payload", "ciphertext"), "A" * 22),
            (("recipients", 0, "wrapped_cek"), "A" * 64),
            (("signature", "value"), "A" * 86),
        ):
            changed = copy.deepcopy(original)
            cursor = changed
            for part in path[:-1]:
                cursor = cursor[part]
            cursor[path[-1]] = replacement
            mutations.append(canonical_bytes(changed))
        mutations.extend((raw + b"\n", b'{"schema":"x","schema":"y"}'))
        for changed in mutations:
            with (
                self.subTest(prefix=changed[:40]),
                self.assertRaisesRegex(SealedDeliveryError, "sealed_delivery_rejected"),
            ):
                open_event(
                    changed,
                    sender_authority=self.authority,
                    local_target=self.targets["legion"],
                    recipient_targets=[
                        self.targets["legion"],
                        self.targets["daimonmatrix"],
                    ],
                    authorization=authorization,
                    custody=self.custodies["legion"],
                    at_ms=NOW + 1,
                )

    def test_wrong_authorization_expiry_and_custody_slot_fail_closed(self) -> None:
        _, targets, authorization, raw = self.envelope()
        changed = copy.deepcopy(dict(authorization.value))
        changed["evidence_hash"] = "0" * 64
        wrong = DisclosureAuthorization(changed)
        for selected_auth, selected_time in (
            (wrong, NOW + 1),
            (authorization, NOW + 60_001),
        ):
            with self.assertRaises(SealedDeliveryError):
                open_event(
                    raw,
                    sender_authority=self.authority,
                    local_target=targets[0],
                    recipient_targets=targets,
                    authorization=selected_auth,
                    custody=self.custodies["legion"],
                    at_ms=selected_time,
                )
        empty = KeystoreDeliveryCustody(
            self.keystores["legion"],
            lambda: bytearray(PASSWORD),
            control_head=self.state.head,
            counter=1,
        )
        with self.assertRaises(SealedDeliveryError):
            open_event(
                raw,
                sender_authority=self.authority,
                local_target=targets[0],
                recipient_targets=targets,
                authorization=authorization,
                custody=empty,
                at_ms=NOW + 1,
            )

    def test_csprng_failure_never_returns_an_envelope(self) -> None:
        event, targets, authorization = self.material()
        with (
            patch("daimon_matrix.sealed.secrets.token_bytes", side_effect=OSError),
            self.assertRaisesRegex(SealedDeliveryError, "sealed_delivery_rejected"),
        ):
            seal_event(
                event,
                sender_authority=self.authority,
                recipients=targets,
                authorization=authorization,
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 30_000,
            )

    def test_revoked_recipient_is_rejected_before_private_operation(self) -> None:
        _, _, authorization, raw = self.envelope()
        revocation = create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id="embodiment:daimonmatrix",
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked_state = verify_successor(revocation, self.state)
        revised_manifest = BeingManifest.from_value(
            {**self.manifest.value, "control_head": revoked_state.head, "revision": 2}
        )
        revoked_authority = RootAuthority(
            revised_manifest,
            revoked_state,
            self.credentials,
            self.incarnations,
        )
        targets = [
            RecipientTarget(revoked_authority, target.credential_id)
            for target in self.targets.values()
        ]
        local = next(
            target
            for target in targets
            if target.credential_id == self.targets["legion"].credential_id
        )
        with self.assertRaises(SealedDeliveryError):
            open_event(
                raw,
                sender_authority=revoked_authority,
                local_target=local,
                recipient_targets=targets,
                authorization=authorization,
                custody=self.custodies["legion"],
                at_ms=NOW + 1,
            )

    def test_rotation_selects_only_new_manifested_recipient_key(self) -> None:
        old_target = self.targets["daimonmatrix"]
        old_credential = self.credentials[old_target.credential_id]
        rotated_private = seed("daimonmatrix-rotated-encryption")
        rotated_credential = create_embodiment_credential(
            self.state,
            self.root_seeds,
            self.signing_seeds["daimonmatrix"],
            x25519_public(rotated_private),
            embodiment_id="embodiment:daimonmatrix",
            body_ref="cluster:daimonmatrix:compaii",
            purposes=["dm.we", "messages"],
            valid_from_ms=NOW - 100,
            valid_until_ms=NOW + 100_000,
            transport_principals=old_credential["body"]["transport_principals"],
        )
        rotated_incarnation = create_incarnation_authorization(
            rotated_credential,
            self.signing_seeds["daimonmatrix"],
            incarnation_id="incarnation:daimonmatrix:1",
            incarnation_sequence=1,
            started_at_ms=NOW - 5,
        )
        credentials = {
            **self.credentials,
            rotated_credential["artifact_id"]: rotated_credential,
        }
        incarnations = {
            **self.incarnations,
            rotated_incarnation["artifact_id"]: rotated_incarnation,
        }
        rows = copy.deepcopy(self.manifest.value["embodiments"])
        row = next(
            item for item in rows if item["embodiment_id"] == "embodiment:daimonmatrix"
        )
        row.update(
            embodiment_credential_id=rotated_credential["artifact_id"],
            incarnation_authorization_id=rotated_incarnation["artifact_id"],
            incarnation_id="incarnation:daimonmatrix:1",
        )
        rows.sort(key=lambda item: (item["embodiment_id"], item["incarnation_id"]))
        manifest = BeingManifest.from_value(
            {**self.manifest.value, "embodiments": rows, "revision": 2}
        )
        authority = RootAuthority(manifest, self.state, credentials, incarnations)
        rotated_target = RecipientTarget(authority, rotated_credential["artifact_id"])
        with self.assertRaises(SealedDeliveryError):
            recipient_descriptor(
                RecipientTarget(authority, old_target.credential_id), at_ms=NOW
            )

        ledger = Ledger(
            self.root_path / "rotated" / "ledger.sqlite",
            authority=authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        event = ledger.append_local(
            kind="experience.observed",
            subject="after recipient rotation",
            payload={"summary": "new key only"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        sender = sender_descriptor(event, authority, at_ms=NOW)
        recipient = recipient_descriptor(rotated_target, at_ms=NOW)
        authorization = DisclosureAuthorization.synthetic(
            event=event,
            sender=sender,
            recipients=[recipient],
            evidence_hash=hashlib.sha256(b"rotated authorization").hexdigest(),
            authorized_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
        )
        directory = self.root_path / "custody-rotated"
        directory.mkdir(mode=0o700)
        slot = "sealed.encryption.v1:daimonmatrix-rotated"
        store = EncryptedKeystore.create(
            directory / "keys.json",
            lambda: bytearray(PASSWORD),
            control_head=self.state.head,
            secrets={slot: rotated_private},
        )
        custody = KeystoreDeliveryCustody(
            store,
            lambda: bytearray(PASSWORD),
            control_head=self.state.head,
            counter=1,
            encryption_slots={recipient["encryption_kid"]: slot},
        )
        raw = seal_event(
            event,
            sender_authority=authority,
            recipients=[rotated_target],
            authorization=authorization,
            custody=self.custodies["legion"],
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
        )
        self.assertEqual(
            open_event(
                raw,
                sender_authority=authority,
                local_target=rotated_target,
                recipient_targets=[rotated_target],
                authorization=authorization,
                custody=custody,
                at_ms=NOW + 1,
            )["event_id"],
            event["event_id"],
        )

    def test_two_isolated_receiver_processes_execute_real_decryption(self) -> None:
        event, targets, authorization, raw = self.envelope()
        bootstrap = (
            "import importlib.util,sys\n"
            f"source_root={str(ROOT / 'src')!r}\n"
            "if importlib.util.find_spec('daimon_matrix') is None:\n"
            "    sys.path.insert(0,source_root)\n"
        )
        program = (
            bootstrap
            + """
import base64,json,sys
from pathlib import Path
from daimon_matrix.identity import ControlState
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.sealed import (
    DisclosureAuthorization, KeystoreDeliveryCustody, RecipientTarget, open_event
)
from daimon_matrix.weave import BeingManifest,RootAuthority
b=json.loads(sys.stdin.buffer.read())
state=ControlState(**b['state'])
authority=RootAuthority(
    BeingManifest.from_value(b['manifest']), state,
    {x['artifact_id']:x for x in b['credentials']},
    {x['artifact_id']:x for x in b['incarnations']},
)
targets=[RecipientTarget(authority,x) for x in b['recipient_ids']]
local=RecipientTarget(authority,b['local_id'])
password=base64.urlsafe_b64decode(b['password']+'='*(-len(b['password'])%4))
custody=KeystoreDeliveryCustody(EncryptedKeystore(Path(b['keystore'])),lambda:bytearray(password),control_head=state.head,counter=1,encryption_slots={b['encryption_kid']:b['slot']})
event=open_event(base64.urlsafe_b64decode(b['envelope']+'='*(-len(b['envelope'])%4)),sender_authority=authority,local_target=local,recipient_targets=targets,authorization=DisclosureAuthorization(b['authorization']),custody=custody,at_ms=b['at_ms'])
print(event['event_id'])
"""
        )
        recipient_ids = [target.credential_id for target in targets]
        for label in ("legion", "daimonmatrix"):
            credential = self.credentials[self.targets[label].credential_id]
            encryption_kid = credential["body"]["encryption_key"]["key_id"]
            bundle = {
                "state": asdict(self.state),
                "manifest": self.manifest.value,
                "credentials": list(self.credentials.values()),
                "incarnations": list(self.incarnations.values()),
                "recipient_ids": recipient_ids,
                "local_id": self.targets[label].credential_id,
                "authorization": authorization.value,
                "keystore": str(self.keystores[label].path),
                "encryption_kid": encryption_kid,
                "slot": f"sealed.encryption.v1:{label}",
                "password": b64url(PASSWORD),
                "envelope": b64url(raw),
                "at_ms": NOW + 1,
            }
            result = subprocess.run(
                [sys.executable, "-I", "-c", program],
                input=json.dumps(bundle),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), event["event_id"])


class DurableEnvelopeTests(SealedFixture):
    def test_store_rejects_weak_parent_and_symlink(self) -> None:
        weak = self.root_path / "weak"
        weak.mkdir(mode=0o755)
        with self.assertRaises(SealedDeliveryError):
            EnvelopeStore(weak / "outbox.sqlite")
        target = self.root_path / "real.sqlite"
        target.touch(mode=0o600)
        link = self.root_path / "linked.sqlite"
        link.symlink_to(target)
        with self.assertRaises(SealedDeliveryError):
            EnvelopeStore(link)

    def test_retry_conflict_and_precommit_failure_are_durable(self) -> None:
        event, targets, authorization = self.material()
        store = EnvelopeStore(self.root_path / "outbox.sqlite")
        plan = sealing_plan_hash(
            event,
            authorization,
            targets,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
        )
        calls = 0

        def factory() -> bytes:
            nonlocal calls
            calls += 1
            return seal_event(
                event,
                sender_authority=self.authority,
                recipients=targets,
                authorization=authorization,
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 30_000,
            )

        request_id = "00000000-0000-4000-8000-000000000052"
        first = store.get_or_create(request_id, plan, factory)
        self.assertEqual(store.get_or_create(request_id, plan, factory), first)
        self.assertEqual(calls, 1)
        with self.assertRaises(SealedDeliveryConflict):
            store.get_or_create(request_id, "0" * 64, factory)

        failed_id = "00000000-0000-4000-8000-000000000053"
        with self.assertRaises(RuntimeError):
            store.get_or_create(
                failed_id, plan, lambda: (_ for _ in ()).throw(RuntimeError("kill"))
            )
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM envelopes WHERE request_id = ?", (failed_id,)
                ).fetchone()
            )
            stored = connection.execute(
                "SELECT envelope FROM envelopes WHERE request_id = ?", (request_id,)
            ).fetchone()[0]
        self.assertEqual(stored, first)
        self.assertNotIn(b"encrypted hello", store.path.read_bytes())

    def test_concurrent_exact_request_commits_one_envelope(self) -> None:
        event, targets, authorization = self.material()
        store = EnvelopeStore(self.root_path / "concurrent-outbox.sqlite")
        plan = sealing_plan_hash(
            event,
            authorization,
            targets,
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
        )

        def factory() -> bytes:
            return seal_event(
                event,
                sender_authority=self.authority,
                recipients=targets,
                authorization=authorization,
                custody=self.custodies["legion"],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 30_000,
            )

        request_id = "00000000-0000-4000-8000-000000000054"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: store.get_or_create(request_id, plan, factory), range(16)
                )
            )
        self.assertEqual(len(set(results)), 1)
        with closing(sqlite3.connect(store.path)) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM envelopes").fetchone()[0], 1
            )


class HistoricalInteropTests(unittest.TestCase):
    def test_pinned_pyca_hpke_opens_frozen_dm011_wrap(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "dm011_vectors", ROOT / "tests/test_dm011_vectors.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        delivery = module.load_artifact("me1/sealed-delivery-1.json")
        row = delivery["recipients"][0]
        private = module._recipient_privs()[row["encryption_kid"]]
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)
        cek = suite.decrypt(
            module.ub64(row["enc"], 32) + module.ub64(row["wrapped_cek"], 48),
            private,
            info=module.hpke_info_for(module.protected_metadata(delivery), row),
        )
        self.assertEqual(len(cek), 32)
        self.assertEqual(KEM.X25519.enc_length(), 32)

    def test_installed_module_exposes_real_hpke_profile(self) -> None:
        program = (
            "import importlib.util,sys;"
            f"source_root={str(ROOT / 'src')!r};"
            "sys.path.insert(0,source_root) "
            "if importlib.util.find_spec('daimon_matrix') is None else None;"
            "import cryptography,daimon_matrix.sealed as s;"
            "assert cryptography.__version__=='50.0.0';"
            "assert s.PROFILE.startswith('HPKE-X25519');"
            "print(s.SCHEMA)"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", program],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.stdout.strip(), "dm.sealed-delivery/v1")


class SchemaTests(unittest.TestCase):
    def test_public_schemas_are_closed_and_valid(self) -> None:
        for name in (
            "sealed-delivery.schema.json",
            "disclosure-authorization-input.schema.json",
        ):
            schema = json.loads((ROOT / "schemas/communication/v1" / name).read_bytes())
            Draft202012Validator.check_schema(schema)

    def test_crypto_dependency_manifest_matches_lock_and_runtime(self) -> None:
        import cryptography

        manifest = json.loads(
            (ROOT / "provenance/cryptography-hpke-v1.json").read_bytes()
        )
        self.assertEqual(cryptography.__version__, manifest["version"])
        self.assertEqual(manifest["license_expression"], "Apache-2.0 OR BSD-3-Clause")
        lock = (ROOT / "uv.lock").read_text()
        for artifact in manifest["artifacts"]:
            self.assertIn(artifact["filename"], lock)
            self.assertIn(artifact["sha256"], lock)


class TribeMembershipFixture(unittest.TestCase):
    """Two beings in one verified tribe, from source-only synthetic fixtures.

    Deliberately avoids `tests.test_native_messaging`: this file runs in CI's
    minimal wheel and conformance environments, where the MCP dependency that
    module pulls in through the daemon is not installed.
    """

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dm051-tribe-")
        self.addCleanup(temporary.cleanup)
        self.journey = _Journey(Path(temporary.name))
        self.journey.run()
        self.events = self.journey.store.events()
        self.founder = self.journey.identities["founder"]
        self.member = self.journey.identities["member"]
        self.authorizer = MembershipAuthorizer(self.events)
        self.now = self.journey.now
        self.tribe_ref = next(
            event["payload"]["tribe_ref"]
            for event in self.events
            if event["kind"] == ACCEPTANCE_KIND
            and event["payload"].get("invitee_being_ref") == self.member.state.being_ref
        )
        with self.journey.store.authorization_view(
            at_ms=self.now, card_verifier=self.journey.card_verifier
        ) as view:
            self.snapshot = view.snapshot(self.tribe_ref)
        self.members = list(self.snapshot.value["members"])
        self.declaration = next(
            event for event in self.events if event["kind"] == DECLARATION_KIND
        )
        self.membership_ref = self._membership_of(self.member.state.being_ref)
        self.sender_custody = self.journey.custody("founder")
        self.receiver_custody = self.journey.custody("member")
        self.bodies = {
            identity.state.being_ref: RecipientTarget(
                self.journey.authorities[identity.state.being_ref],
                identity.credential["artifact_id"],
            )
            for identity in (self.founder, self.member)
        }
        self.target = self.bodies[self.member.state.being_ref]

    def _membership_of(self, being_ref: str) -> str:
        return str(
            next(
                row["membership_ref"]
                for row in self.members
                if row["principal_id"] == being_ref
            )
        )

    def sender_proof(self) -> dict[str, Any]:
        return self.authorizer.proof(
            membership_ref=self.declaration["event_id"],
            tribe_ref=self.tribe_ref,
            principal_id=self.founder.state.being_ref,
        )

    def audience(self) -> list[RecipientTarget]:
        """Every active member's body, the author included, as the spec requires."""
        return [
            self.bodies[str(row["principal_id"])]
            for row in self.members
            if row["state"] == "active"
        ]

    def targets(self) -> list[dict[str, Any]]:
        return sorted(
            (
                {
                    "evidence_cursor": "dm:scope-evidence:v1:" + "A" * 43,
                    "receipt_origin_embodiment_id": row["embodiment_id"],
                    "recipient_id": row["membership_ref"],
                    "recipient_type": "relationship",
                    "scope_kind": "relationship",
                }
                for row in self.members
                if row["state"] == "active"
            ),
            key=lambda row: (
                row["recipient_type"],
                row["recipient_id"],
                row["receipt_origin_embodiment_id"],
            ),
        )

    def author(self, *, scope: str = "/tribe") -> tuple[dict[str, Any], dict[str, Any]]:
        message = create_event(
            self.founder.authority,
            self.founder.origin,
            self.founder.signer,
            event_id=str(uuid.uuid4()),
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=self.now,
            causal_parents=(),
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "body": {"text": "hola tribu"},
                "intent": {
                    "operation": "tribe.converse",
                    "scope": scope,
                    "thread_id": str(uuid.uuid4()),
                },
                "reply": None,
            },
        )
        resolution = create_event(
            self.founder.authority,
            self.founder.origin,
            self.founder.signer,
            event_id=str(uuid.uuid4()),
            sequence=2,
            previous_event_id=message["event_id"],
            occurred_at_ms=self.now,
            causal_parents=(message["event_id"],),
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": scope,
                "targets": self.targets(),
            },
        )
        return message, resolution

    def authorize(
        self,
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
        *,
        memberships: Mapping[str, Mapping[str, Any]] | None = None,
        sender_membership: Mapping[str, Any] | None = None,
        tribe_ref: str | None = None,
        recipient_targets: Sequence[RecipientTarget] | None = None,
    ) -> DisclosureAuthorization:
        return DisclosureAuthorization.from_membership_resolution_event(
            event=message,
            resolution_event=resolution,
            sender_authority=self.founder.authority,
            recipient_targets=(
                self.audience()
                if recipient_targets is None
                else list(recipient_targets)
            ),
            memberships=(
                self.authorizer.proofs(members=self.members, tribe_ref=self.tribe_ref)
                if memberships is None
                else memberships
            ),
            sender_membership=(
                self.sender_proof() if sender_membership is None else sender_membership
            ),
            tribe_ref=self.tribe_ref if tribe_ref is None else tribe_ref,
            expires_at_ms=self.now + 30_000,
        )


class MembershipSealingTests(TribeMembershipFixture):
    """Tribe conversation authority is membership, and never a grant."""

    def test_membership_alone_seals_and_opens_across_beings(self) -> None:
        message, resolution = self.author()
        authorization = self.authorize(message, resolution)
        self.assertEqual(
            sorted(row["being_ref"] for row in authorization.value["recipients"]),
            sorted([self.founder.state.being_ref, self.member.state.being_ref]),
        )
        audience = self.audience()
        raw = seal_event(
            message,
            sender_authority=self.founder.authority,
            recipients=audience,
            authorization=authorization,
            custody=self.sender_custody,
            issued_at_ms=self.now,
            expires_at_ms=self.now + 30_000,
        )
        opened = open_event(
            raw,
            sender_authority=self.founder.authority,
            local_target=self.target,
            recipient_targets=audience,
            authorization=authorization,
            custody=self.receiver_custody,
            at_ms=self.now + 1,
        )
        self.assertEqual(opened["event_id"], message["event_id"])
        self.assertEqual(opened["payload"]["body"]["text"], "hola tribu")

    def test_a_grant_cannot_be_smuggled_into_a_membership_proof(self) -> None:
        """The proof is closed, so conversation cannot carry resource authority."""
        message, resolution = self.author()
        proofs = self.authorizer.proofs(members=self.members, tribe_ref=self.tribe_ref)
        widened = {
            reference: {
                **proof,
                "grant_refs": ["dm:grant:v1:" + "B" * 43],
                "resource_ref": "cluster:synthetic:store",
            }
            for reference, proof in proofs.items()
        }
        with self.assertRaises(SealedDeliveryError):
            self.authorize(message, resolution, memberships=widened)

    def test_membership_failures_are_closed(self) -> None:
        message, resolution = self.author()
        proofs = self.authorizer.proofs(members=self.members, tribe_ref=self.tribe_ref)
        inactive = {
            self.membership_ref: {**proofs[self.membership_ref], "active": False}
        }
        other_tribe = {
            self.membership_ref: {
                **proofs[self.membership_ref],
                "tribe_ref": "dm:tribe:v1:" + "C" * 43,
            }
        }
        stranger = {
            self.membership_ref: {
                **proofs[self.membership_ref],
                "member_being_ref": self.founder.state.being_ref,
            }
        }
        cases: dict[str, dict[str, Any]] = {
            "inactive": {"memberships": inactive},
            "other_tribe": {"memberships": other_tribe},
            "proof_for_another_being": {"memberships": stranger},
            "membership_absent": {"memberships": {}},
            "sender_not_a_member": {
                "sender_membership": {**self.sender_proof(), "active": False}
            },
            "sender_membership_missing": {"sender_membership": {}},
            "no_recipient_supplied": {"recipient_targets": []},
        }
        for name, kwargs in cases.items():
            with self.subTest(case=name), self.assertRaises(SealedDeliveryError):
                self.authorize(message, resolution, **kwargs)

    def test_a_non_tribe_scope_cannot_use_the_membership_profile(self) -> None:
        message, resolution = self.author(scope="/we")
        with self.assertRaises(SealedDeliveryError):
            self.authorize(message, resolution)

    def sealed_envelope(
        self, message: Mapping[str, Any], authorization: DisclosureAuthorization
    ) -> bytes:
        return seal_event(
            message,
            sender_authority=self.founder.authority,
            recipients=self.audience(),
            authorization=authorization,
            custody=self.sender_custody,
            issued_at_ms=self.now,
            expires_at_ms=self.now + 30_000,
        )

    def rebuild(
        self,
        envelope: Mapping[str, Any],
        resolution: Mapping[str, Any],
        *,
        tribe_ref: str | None = None,
        message_hash: str | None = None,
    ) -> DisclosureAuthorization:
        """What a receiver can do with the header, the resolution and its own proofs."""
        return DisclosureAuthorization.from_membership_resolution_identity(
            message_id=str(envelope["event_id"]),
            message_hash=(
                str(envelope["event_hash"]) if message_hash is None else message_hash
            ),
            sensitivity=str(envelope["sensitivity"]),
            resolution_event=resolution,
            sender_authority=self.founder.authority,
            recipient_targets=self.audience(),
            memberships=self.authorizer.proofs(
                members=self.members, tribe_ref=self.tribe_ref
            ),
            sender_membership=self.sender_proof(),
            tribe_ref=self.tribe_ref if tribe_ref is None else tribe_ref,
            expires_at_ms=int(envelope["expires_at_ms"]),
            authorization_id=str(envelope["authorization_id"]),
        )

    def test_a_receiver_rebuilds_the_exact_authorization_before_decrypting(
        self,
    ) -> None:
        message, resolution = self.author()
        sender_authorization = self.authorize(message, resolution)
        raw = self.sealed_envelope(message, sender_authorization)
        envelope = _parse(raw)
        rebuilt = self.rebuild(envelope, resolution)
        self.assertEqual(rebuilt.value, sender_authorization.value)
        opened = open_event(
            raw,
            sender_authority=self.founder.authority,
            local_target=self.target,
            recipient_targets=self.audience(),
            authorization=rebuilt,
            custody=self.receiver_custody,
            at_ms=self.now + 1,
        )
        self.assertEqual(opened["event_id"], message["event_id"])

    def test_a_renamed_tribe_cannot_rebuild_the_authorization(self) -> None:
        """The tribe ref is bound through the proofs, so renaming it fails closed."""
        message, resolution = self.author()
        raw = self.sealed_envelope(message, self.authorize(message, resolution))
        envelope = _parse(raw)
        with self.assertRaises(SealedDeliveryError):
            self.rebuild(envelope, resolution, tribe_ref="dm:tribe:v1:" + "C" * 43)

    def test_a_claimed_message_identity_that_is_not_the_event_fails(self) -> None:
        """Claiming an identity is safe only because opening must match it."""
        message, resolution = self.author()
        raw = self.sealed_envelope(message, self.authorize(message, resolution))
        envelope = _parse(raw)
        forged = self.rebuild(envelope, resolution, message_hash="f" * 64)
        with self.assertRaises(SealedDeliveryError):
            open_event(
                raw,
                sender_authority=self.founder.authority,
                local_target=self.target,
                recipient_targets=self.audience(),
                authorization=forged,
                custody=self.receiver_custody,
                at_ms=self.now + 1,
            )


class MembershipAuthorizerTests(TribeMembershipFixture):
    """Proofs come from signed history, or the member is not proved at all."""

    def test_active_members_are_proved_from_the_verified_snapshot(self) -> None:
        proofs = self.authorizer.proofs(members=self.members, tribe_ref=self.tribe_ref)
        self.assertEqual(
            set(proofs),
            {row["membership_ref"] for row in self.members if row["state"] == "active"},
        )
        proof = proofs[self.membership_ref]
        source = next(
            event for event in self.events if event["event_id"] == self.membership_ref
        )
        self.assertEqual(proof["schema"], MEMBERSHIP_PROOF_SCHEMA)
        self.assertIs(proof["active"], True)
        self.assertEqual(proof["member_being_ref"], self.member.state.being_ref)
        self.assertEqual(proof["tribe_ref"], self.tribe_ref)
        self.assertEqual(proof["membership_event_id"], source["event_id"])
        self.assertEqual(proof["membership_event_hash"], source["content_hash"])
        self.assertEqual(
            set(proof),
            {
                "active",
                "member_being_ref",
                "membership_event_hash",
                "membership_event_id",
                "membership_ref",
                "schema",
                "tribe_ref",
            },
        )

    def test_the_founder_is_proved_from_the_declaration(self) -> None:
        """A declaration names no being ref, so the principal must be one."""
        founder_membership = self._membership_of(self.founder.state.being_ref)
        self.assertEqual(founder_membership, self.declaration["event_id"])
        proof = self.sender_proof()
        self.assertEqual(proof["member_being_ref"], self.founder.state.being_ref)
        with self.assertRaises(TribeConversationError) as caught:
            self.authorizer.proof(
                membership_ref=self.declaration["event_id"],
                tribe_ref=self.tribe_ref,
                principal_id="synthetic-founder@loopback",
            )
        self.assertEqual(str(caught.exception), "membership_being_ref_invalid")

    def test_a_snapshot_that_renames_a_member_conflicts(self) -> None:
        renamed = [
            {
                **row,
                "principal_id": (
                    self.founder.state.being_ref
                    if row["principal_id"] == self.member.state.being_ref
                    else row["principal_id"]
                ),
            }
            for row in self.members
        ]
        with self.assertRaises(TribeConversationError) as caught:
            self.authorizer.proofs(members=renamed, tribe_ref=self.tribe_ref)
        self.assertEqual(str(caught.exception), "membership_proof_conflict")

    def test_a_member_the_history_cannot_prove_is_absent_not_guessed(self) -> None:
        unknown = [
            {
                **row,
                "membership_ref": "dm:membership:v1:" + "A" * 43,
            }
            for row in self.members
            if row["principal_id"] == self.member.state.being_ref
        ]
        with self.assertRaises(TribeConversationError) as caught:
            self.authorizer.proofs(members=unknown, tribe_ref=self.tribe_ref)
        self.assertEqual(str(caught.exception), "membership_proof_unavailable")

    def test_removed_members_are_skipped_and_an_empty_audience_fails_closed(
        self,
    ) -> None:
        for state in ("left", "expelled"):
            with self.subTest(state=state):
                removed = [{**row, "state": state} for row in self.members]
                with self.assertRaises(TribeConversationError) as caught:
                    self.authorizer.proofs(members=removed, tribe_ref=self.tribe_ref)
                self.assertEqual(str(caught.exception), "tribe_audience_empty")

    def test_duplicated_membership_refs_fail_closed(self) -> None:
        only = next(
            row
            for row in self.members
            if row["principal_id"] == self.member.state.being_ref
        )
        with self.assertRaises(TribeConversationError) as caught:
            self.authorizer.proofs(members=[only, dict(only)], tribe_ref=self.tribe_ref)
        self.assertEqual(str(caught.exception), "membership_proof_duplicated")


class TribeConversationLaneTests(TribeMembershipFixture):
    """One tribe message: authored once, sealed once, receipted per body."""

    def setUp(self) -> None:
        super().setUp()
        self.founder_ledger = Ledger(
            Path(self.journey.root) / "founder-tribe.sqlite3",
            authority=self.founder.authority,
            local_origin=self.founder.origin,
            clock=lambda: self.now,
        )
        self.member_ledger = Ledger(
            Path(self.journey.root) / "member-tribe.sqlite3",
            authority=self.member.authority,
            local_origin=self.member.origin,
            clock=lambda: self.now,
        )
        self.sender_lane = self.lane_for(
            "founder", self.founder_ledger, self.sender_custody, self.journey.store
        )
        self.receiver_lane = self.lane_for(
            "member", self.member_ledger, self.receiver_custody, self.journey.peer_store
        )

    def lane_for(
        self,
        label: str,
        ledger: Ledger,
        custody: KeystoreDeliveryCustody,
        relationships: Any,
        *,
        at_ms: int | None = None,
    ) -> TribeConversation:
        identity = self.journey.identities[label]
        return TribeConversation(
            ledger,
            signer=identity.signer,
            custody=custody,
            clock=lambda: self.now if at_ms is None else at_ms,
            relationships=relationships,
            card_verifier=self.journey.card_verifier,
            authority_resolver=lambda ref: self.journey.authorities[ref],
        )

    def test_one_message_reaches_the_member_and_comes_back_signed(self) -> None:
        delivered: list[str] = []

        def carry(embodiment_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
            delivered.append(embodiment_id)
            return self.receiver_lane.intake(payload)

        result = self.sender_lane.converse(
            text="hola tribu",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.tribe_ref,
            ttl_ms=30_000,
            deliver=carry,
        )
        self.assertEqual(result["schema"], TRIBE_CONVERSE_RESULT_SCHEMA)
        self.assertEqual(result["tribe_ref"], self.tribe_ref)
        # The author is inside the sealed carrier set but is not delivered to.
        self.assertEqual(delivered, [self.member.origin["embodiment_id"]])
        self.assertEqual(
            sorted(
                (row["state"], row["embodiment_id"]) for row in result["deliveries"]
            ),
            sorted(
                [
                    ("author", self.founder.origin["embodiment_id"]),
                    ("delivered", self.member.origin["embodiment_id"]),
                ]
            ),
        )
        receipt_id = next(
            row["receipt_event_id"]
            for row in result["deliveries"]
            if row["state"] == "delivered"
        )
        # The hearing body signed its own receipt into its own ledger. The foreign
        # message is deliberately not there: it cannot verify against this being's
        # root, and retention of foreign material belongs to the host's stores.
        heard = self.member_ledger.event(receipt_id)
        assert heard is not None
        self.assertEqual(
            heard["origin"]["embodiment_id"], self.member.origin["embodiment_id"]
        )
        self.assertEqual(heard["payload"]["recipient_type"], "relationship")
        self.assertEqual(heard["payload"]["recipient_id"], self.membership_ref)
        self.assertIsNone(self.member_ledger.event(result["message_id"]))
        # The author kept its own message and resolution, and gets the member's
        # verified receipt back so authorship stays visible per body.
        self.assertIsNotNone(self.founder_ledger.event(result["message_id"]))
        self.assertIsNotNone(self.founder_ledger.event(result["resolution_id"]))
        self.assertIsNone(self.founder_ledger.event(receipt_id))
        returned = next(
            row["receipt"]
            for row in result["deliveries"]
            if row["state"] == "delivered"
        )
        self.assertEqual(returned["event_id"], receipt_id)
        self.assertEqual(returned["being_ref"], self.member.state.being_ref)

    def test_an_exact_retry_says_it_once(self) -> None:
        request_id = str(uuid.uuid4())

        def carry(embodiment_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
            return self.receiver_lane.intake(payload)

        first = self.sender_lane.converse(
            text="hola tribu",
            request_id=request_id,
            tribe_ref=self.tribe_ref,
            ttl_ms=30_000,
            deliver=carry,
        )
        second = self.sender_lane.converse(
            text="hola tribu",
            request_id=request_id,
            tribe_ref=self.tribe_ref,
            ttl_ms=30_000,
            deliver=carry,
        )
        self.assertEqual(second["message_id"], first["message_id"])
        self.assertEqual(second["resolution_id"], first["resolution_id"])
        self.assertEqual(second["thread_id"], first["thread_id"])
        messages = [
            event
            for event in self.founder_ledger.events()
            if event["subject"] == "communication"
        ]
        self.assertEqual(len(messages), 1)
        receipts = [
            event
            for event in self.member_ledger.events()
            if event["subject"] == "communication-receipt"
        ]
        self.assertEqual(len(receipts), 1)

    def test_a_non_member_cannot_intake_the_message(self) -> None:
        delegate = self.journey.identities["delegate"]
        delegate_ledger = Ledger(
            Path(self.journey.root) / "delegate-tribe.sqlite3",
            authority=delegate.authority,
            local_origin=delegate.origin,
            clock=lambda: self.now,
        )
        outsider = self.lane_for(
            "delegate",
            delegate_ledger,
            self.journey.custody("delegate"),
            self.journey.peer_store,
        )
        sealed: list[Mapping[str, Any]] = []

        def capture(
            embodiment_id: str, payload: Mapping[str, Any]
        ) -> Mapping[str, Any]:
            sealed.append(payload)
            return self.receiver_lane.intake(payload)

        self.sender_lane.converse(
            text="hola tribu",
            request_id=str(uuid.uuid4()),
            tribe_ref=self.tribe_ref,
            ttl_ms=30_000,
            deliver=capture,
        )
        self.assertEqual(len(sealed), 1)
        with self.assertRaises(TribeConversationError):
            outsider.intake(sealed[0])
        self.assertEqual(
            [
                event
                for event in delegate_ledger.events()
                if event["subject"] == "communication-receipt"
            ],
            [],
        )


if __name__ == "__main__":
    unittest.main()
