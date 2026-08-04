from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sqlite3
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes
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
    DisclosureAuthorization,
    EnvelopeStore,
    KeystoreDeliveryCustody,
    RecipientTarget,
    SealedDeliveryConflict,
    SealedDeliveryError,
    open_event,
    recipient_descriptor,
    seal_event,
    sealing_plan_hash,
    sender_descriptor,
)
from daimon_matrix.weave import BeingManifest, RootAuthority
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


if __name__ == "__main__":
    unittest.main()
