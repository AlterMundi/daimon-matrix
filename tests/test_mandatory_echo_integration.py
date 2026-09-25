from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.daemon import _run_egress_worker
from daimon_matrix.messaging_config import BINDING_DOMAIN, verify_public_binding
from daimon_matrix.native_egress import (
    MandatoryEgressController,
    NativeEgressError,
    OperationBinding,
    _owner_file,
    load_owner_visibility_file,
)

POLICY = {
    "schema": "daimon-visibility-policy/v2",
    "generation": 1,
    "origin": "synthetic-owner-installation",
    "bot_id": 137,
    "chat_id": -137,
    "topic_id": None,
    "representation": "plain-json/v2",
    "acceptance_digest": "a" * 64,
    "proof_key_id": "synthetic-proof-key",
}


class OwnerFileTests(unittest.TestCase):
    def test_owner_file_rejects_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "owner-secret"
            alias = Path(directory) / "owner-secret-alias"
            source.write_bytes(b"owner-only")
            source.chmod(0o600)
            os.link(source, alias)

            with self.assertRaisesRegex(
                NativeEgressError, "^egress_installation_invalid$"
            ):
                _owner_file(source, maximum=64)


class SignedVisibilityInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.owner_key = Ed25519PrivateKey.generate()
        self.peer_key = Ed25519PrivateKey.generate()
        self.application_sha256 = "a" * 64
        self.token = b"137:TEST_ONLY"
        self.proof_key = b"p" * 32
        self._write("telegram.token", self.token)
        self._write("echo-proof.key", self.proof_key)
        destination = {
            "bot_id": 137,
            "chat_id": -137,
            "topic_id": None,
            "representation": "plain-json/v2",
        }
        scope = {
            "mode": "all-inter-daimon-communications",
            "channels": [
                {
                    "channel_id": "owner-to-peer",
                    "direction": "outgoing",
                    "local_being_ref": "dm:being:owner",
                    "peer_being_ref": "dm:being:peer",
                    "bootstrap_policy": {},
                    "relationship_disclosure": {},
                }
            ],
            "projected_content": "complete-plaintext-content-and-metadata",
        }
        self.disclosure: dict[str, Any] = {
            "schema": "dm.messaging.visibility-disclosure/v1",
            "issued_at_ms": 1_900_000_000_000,
            "destination": destination,
            "scope": scope,
            "scope_sha256": hashlib.sha256(canonical_bytes(scope)).hexdigest(),
            "participants": ["dm:being:owner", "dm:being:peer"],
            "risk": (
                "all-inter-daimon-communication-will-be-posted-as-plaintext-"
                "to-the-fixed-telegram-destination"
            ),
        }
        self.identities = {
            "dm:being:owner": self._identity("dm:being:owner", "owner-runtime"),
            "dm:being:peer": self._identity("dm:being:peer", "peer-runtime"),
        }
        self.keys = {
            "dm:being:owner": self.owner_key,
            "dm:being:peer": self.peer_key,
        }
        acceptance_set = {
            "schema": "dm.messaging.visibility-acceptance-set/v1",
            "disclosure_sha256": self._digest(self.disclosure),
            "bindings": [
                self._binding(participant, self.disclosure)
                for participant in self.disclosure["participants"]
            ],
        }
        policy = {
            "schema": "daimon-visibility-policy/v2",
            "generation": 1,
            "origin": "owner-signed-installation",
            "bot_id": 137,
            "chat_id": -137,
            "topic_id": None,
            "representation": "plain-json/v2",
            "acceptance_digest": self._digest(acceptance_set),
            "proof_key_id": "sha256:" + hashlib.sha256(self.proof_key).hexdigest(),
        }
        self.document: dict[str, Any] = {
            "schema": "dm.messaging.visibility-installation/v1",
            "generation": 1,
            "runtime_id": "owner-runtime",
            "application_sha256": self.application_sha256,
            "disclosure": self.disclosure,
            "acceptance_set": acceptance_set,
            "policy": policy,
            "secrets": {
                "telegram_token_file": "telegram.token",
                "telegram_token_sha256": hashlib.sha256(self.token).hexdigest(),
                "proof_key_file": "echo-proof.key",
            },
            "telegram_qualification": {
                "schema": "dm.messaging.telegram-qualification/v1",
                "qualified_at_ms": 1_900_000_000_000,
                "token_sha256": hashlib.sha256(self.token).hexdigest(),
                "get_me_bot_id": 137,
                "probe_chat_id": -137,
                "probe_topic_id": None,
                "probe_message_id": 42,
                "probe_text_sha256": "b" * 64,
            },
        }

    @staticmethod
    def _digest(value: object) -> str:
        return hashlib.sha256(canonical_bytes(value)).hexdigest()

    @staticmethod
    def _identity(being_ref: str, runtime_id: str) -> dict[str, object]:
        return {
            "runtime_id": runtime_id,
            "runtime_label": runtime_id,
            "being_ref": being_ref,
            "origin": {
                "body_ref": "body",
                "embodiment_id": "embodiment",
                "incarnation_id": "incarnation",
                "principal_id": "principal",
            },
            "control_head": "head",
            "manifest_hash": "c" * 64,
            "credential_id": "credential",
            "incarnation_authorization_id": "incarnation-authorization",
            "signing_key_id": "signing-key",
        }

    def _binding(self, participant: str, document: object) -> dict[str, object]:
        body = {
            **self.identities[participant],
            "application_sha256": self._digest(document),
        }
        signature = self.keys[participant].sign(BINDING_DOMAIN + canonical_bytes(body))
        return {
            "schema": "dm.messaging.operator-binding/v1",
            "body": body,
            "signature": b64url(signature),
        }

    def _write(self, name: str, raw: bytes) -> None:
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)

    def _write_envelope(self, document: dict[str, object]) -> Path:
        envelope = {
            "document": document,
            "binding": self._binding("dm:being:owner", document),
        }
        path = self.root / "visibility.json"
        path.write_bytes(canonical_bytes(envelope))
        path.chmod(0o600)
        return path

    def _verify_owner(self, document: object, binding: object) -> None:
        verify_public_binding(
            self.identities["dm:being:owner"],
            self.owner_key.public_key().public_bytes_raw(),
            document,
            binding,
        )

    def _verify_participant(
        self, participant: str, document: object, binding: object
    ) -> None:
        verify_public_binding(
            self.identities[participant],
            self.keys[participant].public_key().public_bytes_raw(),
            document,
            binding,
        )

    def _load(self, document: dict[str, object]) -> MandatoryEgressController:
        return load_owner_visibility_file(
            self._write_envelope(document),
            expected_application_sha256=self.application_sha256,
            verify_owner_binding=self._verify_owner,
            verify_participant_binding=self._verify_participant,
            clock=lambda: 1_900_000_000_001,
        )

    def test_owner_signed_installation_loads_offline_and_binds_all_inputs(self) -> None:
        controller = self._load(self.document)

        self.assertTrue(controller.release_enabled)
        self.assertEqual(
            controller.policy_digest, self._digest(self.document["policy"])
        )
        self.assertEqual(controller.installation_digest, self._digest(self.document))
        self.assertEqual(controller.owner_actor, "dm:being:owner")

    def test_installation_rejects_tampered_signature_and_document(self) -> None:
        path = self._write_envelope(self.document)
        envelope = json.loads(path.read_bytes())
        envelope["binding"]["signature"] = "A" * 86
        path.write_bytes(canonical_bytes(envelope))
        with self.assertRaisesRegex(NativeEgressError, "egress_installation_invalid"):
            load_owner_visibility_file(
                path,
                expected_application_sha256=self.application_sha256,
                verify_owner_binding=self._verify_owner,
                verify_participant_binding=self._verify_participant,
            )
        altered = copy.deepcopy(self.document)
        altered["generation"] = 2
        envelope = {
            "document": altered,
            "binding": self._binding("dm:being:owner", self.document),
        }
        path.write_bytes(canonical_bytes(envelope))
        with self.assertRaisesRegex(NativeEgressError, "egress_installation_invalid"):
            load_owner_visibility_file(
                path,
                expected_application_sha256=self.application_sha256,
                verify_owner_binding=self._verify_owner,
                verify_participant_binding=self._verify_participant,
            )

    def test_installation_rejects_mismatched_closed_digest_relationships(self) -> None:
        mutations: tuple[Callable[[dict[str, Any]], None], ...] = (
            lambda d: d.update(application_sha256="d" * 64),
            lambda d: d.update(runtime_id="other-runtime"),
            lambda d: d["policy"].update(chat_id=-999),
            lambda d: d["telegram_qualification"].update(get_me_bot_id=999),
            lambda d: d["telegram_qualification"].update(token_sha256="e" * 64),
            lambda d: d["policy"].update(proof_key_id="sha256:" + "f" * 64),
            lambda d: d["acceptance_set"].update(disclosure_sha256="0" * 64),
            lambda d: d["policy"].update(acceptance_digest="1" * 64),
        )
        for mutate in mutations:
            document = copy.deepcopy(self.document)
            mutate(document)
            with (
                self.subTest(document=document),
                self.assertRaisesRegex(
                    NativeEgressError, "egress_installation_invalid"
                ),
            ):
                self._load(document)

    def test_installation_rejects_replaced_secrets_and_participant_binding(
        self,
    ) -> None:
        for leaf, replacement in (
            ("telegram.token", b"137:REPLACED"),
            ("echo-proof.key", b"q" * 32),
        ):
            original = (self.root / leaf).read_bytes()
            self._write(leaf, replacement)
            with (
                self.subTest(leaf=leaf),
                self.assertRaisesRegex(
                    NativeEgressError, "egress_installation_invalid"
                ),
            ):
                self._load(self.document)
            self._write(leaf, original)
        document = copy.deepcopy(self.document)
        document["acceptance_set"]["bindings"][1]["signature"] = "A" * 86
        document["policy"]["acceptance_digest"] = self._digest(
            document["acceptance_set"]
        )
        with self.assertRaisesRegex(NativeEgressError, "egress_installation_invalid"):
            self._load(document)

    def test_installation_secret_references_are_relative_safe_leaves(self) -> None:
        for value in ("../telegram.token", str(self.root / "telegram.token"), "a/b"):
            document = copy.deepcopy(self.document)
            document["secrets"]["telegram_token_file"] = value
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    NativeEgressError, "egress_installation_invalid"
                ),
            ):
                self._load(document)


def control_projection(operation_id: str) -> dict[str, object]:
    return {
        "event_id": operation_id,
        "event_digest": hashlib.sha256(operation_id.encode()).hexdigest(),
        "sender": "dm:being:v1:alice/embodiment-a",
        "recipients": ["dm:being:v1:bob/embodiment-b"],
        "thread_id": "dm137-integration",
        "reply_to": None,
        "kind": "authorization-control",
        "content": {"stage": "evidence-before-message"},
    }


class TelegramTransport:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.send: Callable[[dict[str, object]], bytes] = self._send

    def _send(self, request: dict[str, object]) -> bytes:
        self.calls.append(request)
        result: dict[str, object] = {
            "message_id": len(self.calls),
            "from": {"id": 137, "is_bot": True},
            "chat": {"id": request["chat_id"]},
            "text": request["text"],
        }
        return json.dumps(
            {"ok": True, "result": result}, separators=(",", ":")
        ).encode()


class MandatoryEchoIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "native.sqlite"
        self.now = 1_900_000_000_000
        self.current = True
        self.transport = TelegramTransport()
        self.owner_key = Ed25519PrivateKey.generate()
        self.owner_identity = SignedVisibilityInstallationTests._identity(
            "dm:being:owner", "owner-runtime"
        )
        with closing(sqlite3.connect(self.path)) as database:
            database.execute(
                "CREATE TABLE native_operations ("
                "operation_id TEXT PRIMARY KEY, payload BLOB NOT NULL)"
            )
        self.controller = MandatoryEgressController(
            policy=POLICY,
            proof_key=b"k" * 32,
            transport=self.transport,
            clock=lambda: self.now,
            catalog_mode="synthetic",
            installation_digest="1" * 64,
            owner_actor="dm:being:owner",
            verify_owner_binding=self._verify_owner,
        )
        self.controller.register_catalog(
            catalog_id="integration-native",
            path=self.path,
            resolve=self._resolve,
            authorize=lambda _binding: self.current,
        )
        self.controller.register_path("peer-scope-request", "integration-native")

    def _resolve(self, locator: str) -> bytes:
        with closing(sqlite3.connect(self.path)) as database:
            row = database.execute(
                "SELECT payload FROM native_operations WHERE operation_id=?", (locator,)
            ).fetchone()
        if row is None:
            raise ValueError("missing")
        return bytes(row[0])

    def _verify_owner(self, document: object, binding: object) -> None:
        verify_public_binding(
            self.owner_identity,
            self.owner_key.public_key().public_bytes_raw(),
            document,
            binding,
        )

    def _signed_retry(
        self,
        binding: OperationBinding,
        *,
        change: Callable[[dict[str, Any]], None] | None = None,
        authorization_id: str = "00000000-0000-4000-8000-000000000137",
    ) -> bytes:
        challenge = self.controller.ambiguity_challenge(binding)
        decision = {
            "authorization_id": authorization_id,
            "actor": "dm:being:owner",
            "operation_id": challenge["echo_operation_id"],
            "binding_digest": challenge["echo_binding_digest"],
            "attempt_id": challenge["latest_attempt_id"],
            "approved_at_ms": self.now,
            "expires_at_ms": self.now + 60_000,
            "risk": "duplicate-platform-post-accepted",
        }
        command = {
            "schema": "dm.messaging.echo-retry-command/v1",
            "resolution": "retry-ambiguous",
            "visibility_installation_sha256": challenge[
                "visibility_installation_sha256"
            ],
            "policy_sha256": challenge["policy_sha256"],
            "catalog_id": challenge["catalog_id"],
            "path_id": challenge["path_id"],
            "native_operation_id": challenge["native_operation_id"],
            "decision": decision,
        }
        if change is not None:
            change(command)
        body = {
            **self.owner_identity,
            "application_sha256": hashlib.sha256(canonical_bytes(command)).hexdigest(),
        }
        signature = self.owner_key.sign(BINDING_DOMAIN + canonical_bytes(body))
        return canonical_bytes(
            {
                "command": command,
                "binding": {
                    "schema": "dm.messaging.operator-binding/v1",
                    "body": body,
                    "signature": b64url(signature),
                },
            }
        )

    def _admit(
        self,
        operation_id: str,
        payload: bytes = b"native-request",
        path_id: str = "peer-scope-request",
    ) -> OperationBinding:
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO native_operations VALUES (?, ?)", (operation_id, payload)
            )
            binding = self.controller.admit_in_transaction(
                database,
                catalog_id="integration-native",
                path_id=path_id,
                operation_id=operation_id,
                locator=operation_id,
                native_bytes=payload,
                projection=control_projection(operation_id),
                deadline_ms=self.now + 600_000,
                authority_head="authority-head-1",
            )
            database.commit()
        return binding

    def test_registry_health_is_bounded_and_closure_blocks_registration(self) -> None:
        open_status = self.controller.status()
        self.assertEqual(open_status["registry_state"], "open")
        self.assertEqual(open_status["registered_catalogs"], 1)
        self.assertEqual(open_status["registered_paths"], 1)
        self.assertFalse(open_status["registry_healthy"])
        self.assertNotIn(str(self.path), json.dumps(open_status))

        self.controller.validate_registry({"peer-scope-request"})
        closed_status = self.controller.status()
        self.assertEqual(closed_status["registry_state"], "closed")
        self.assertTrue(closed_status["registry_healthy"])
        with self.assertRaisesRegex(NativeEgressError, "egress_catalog_invalid"):
            self.controller.register_catalog(
                catalog_id="integration-native",
                path=self.path,
                resolve=self._resolve,
                authorize=lambda binding: self.current,
            )
        with self.assertRaisesRegex(NativeEgressError, "egress_path_registry_invalid"):
            self.controller.register_path("peer-sync-request", "integration-native")

    def test_admission_rejects_unregistered_path_and_wrong_catalog_pair(self) -> None:
        second = Path(self.temporary.name) / "second.sqlite"
        with closing(sqlite3.connect(second)) as database:
            database.execute(
                "CREATE TABLE native_operations ("
                "operation_id TEXT PRIMARY KEY, payload BLOB NOT NULL)"
            )
        self.controller.register_catalog(
            catalog_id="integration-second",
            path=second,
            resolve=lambda locator: b"wrong-catalog",
            authorize=lambda binding: True,
        )
        with closing(sqlite3.connect(second)) as database:
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            for catalog_id, path_id in (
                ("integration-native", "peer-sync-request"),
                ("integration-second", "peer-scope-request"),
            ):
                with self.assertRaisesRegex(
                    NativeEgressError, "egress_operation_invalid"
                ):
                    self.controller.admit_in_transaction(
                        database,
                        catalog_id=catalog_id,
                        path_id=path_id,
                        operation_id=f"refused-{catalog_id}",
                        locator="refused",
                        native_bytes=b"wrong-catalog",
                        projection=control_projection(f"refused-{catalog_id}"),
                        deadline_ms=self.now + 60_000,
                        authority_head="authority-head-1",
                    )
            database.rollback()

    def test_atomic_admission_rolls_back_with_authoritative_native_operation(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO native_operations VALUES ('rolled-back', X'01')"
            )
            self.controller.admit_in_transaction(
                database,
                catalog_id="integration-native",
                path_id="peer-scope-request",
                operation_id="rolled-back",
                locator="rolled-back",
                native_bytes=b"\x01",
                projection=control_projection("rolled-back"),
                deadline_ms=self.now + 60_000,
                authority_head="authority-head-1",
            )
            database.rollback()
        with closing(sqlite3.connect(self.path)) as database:
            self.assertIsNone(
                database.execute(
                    "SELECT 1 FROM native_operations WHERE operation_id='rolled-back'"
                ).fetchone()
            )
            self.assertIsNone(
                database.execute(
                    "SELECT 1 FROM mandatory_egress_operations "
                    "WHERE operation_id='rolled-back'"
                ).fetchone()
            )

    def test_release_requires_confirmation_current_authority_and_one_call_permit(
        self,
    ) -> None:
        # Inter-daimon message egress keeps its confirmed echo. The intra-being
        # /we lane is covered by the peer transport suite, where the mirror
        # transport is down for the whole test and the release still succeeds.
        self.controller.register_path("messaging-message-request", "integration-native")
        binding = self._admit("scope-operation", path_id="messaging-message-request")
        native_calls: list[bytes] = []
        self.controller.release(binding, b"native-request", native_calls.append)
        self.assertEqual(native_calls, [b"native-request"])
        self.assertEqual(self.controller.inspect(binding)["state"], "confirmed")

        self.current = False
        with self.assertRaisesRegex(NativeEgressError, "egress_authority_blocked"):
            self.controller.release(binding, b"native-request", native_calls.append)
        self.current = True
        self.controller.release(binding, b"native-request", native_calls.append)
        self.assertEqual(native_calls, [b"native-request"] * 2)

        # An exact native retry receives a fresh one-call permit without reposting
        # Telegram.  The receiver's protocol owns network deduplication.
        self.controller.release(binding, b"native-request", native_calls.append)
        self.assertEqual(native_calls, [b"native-request"] * 3)
        with self.assertRaisesRegex(NativeEgressError, "egress_operation_mismatch"):
            self.controller.release(binding, b"changed", native_calls.append)

    def test_signed_owner_retry_binds_exact_state_and_replays_without_post(
        self,
    ) -> None:
        binding = self._admit("ambiguous-operation")
        original = self.transport.send

        def lost(request: dict[str, object]) -> bytes:
            original(request)
            raise TimeoutError("lost sanitized response")

        self.transport.send = lost
        self.assertEqual(self.controller.advance_one(binding)["state"], "ambiguous")
        authorization = self._signed_retry(binding)
        self.transport.send = original

        self.assertEqual(
            self.controller.retry_ambiguous(binding, authorization)["state"],
            "confirmed",
        )
        sent = len(self.transport.calls)
        self.now += 120_000
        self.assertEqual(
            self.controller.retry_ambiguous(binding, authorization)["state"],
            "confirmed",
        )
        self.assertEqual(len(self.transport.calls), sent)

    def test_signed_owner_retry_rejects_wrong_exact_fields_expiry_and_signature(
        self,
    ) -> None:
        binding = self._admit("rejected-retry")
        self.transport.send = lambda request: (_ for _ in ()).throw(TimeoutError())
        self.controller.advance_one(binding)
        changes = (
            lambda c: c.update(visibility_installation_sha256="2" * 64),
            lambda c: c.update(policy_sha256="2" * 64),
            lambda c: c.update(catalog_id="wrong-catalog"),
            lambda c: c.update(path_id="peer-sync-request"),
            lambda c: c.update(native_operation_id="wrong-native"),
            lambda c: c["decision"].update(operation_id="wrong-echo"),
            lambda c: c["decision"].update(binding_digest="2" * 64),
            lambda c: c["decision"].update(attempt_id="wrong-attempt"),
            lambda c: c["decision"].update(actor="dm:being:peer"),
            lambda c: c["decision"].update(
                expires_at_ms=c["decision"]["approved_at_ms"] + 60_001
            ),
            lambda c: c["decision"].update(risk="duplicate-risk-not-accepted"),
        )
        before = len(self.transport.calls)
        for change in changes:
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(NativeEgressError, "egress_retry_unauthorized"),
            ):
                self.controller.retry_ambiguous(
                    binding, self._signed_retry(binding, change=change)
                )
        expired = self._signed_retry(binding)
        self.now += 60_000
        with self.assertRaisesRegex(NativeEgressError, "egress_retry_unauthorized"):
            self.controller.retry_ambiguous(binding, expired)
        tampered = json.loads(self._signed_retry(binding))
        tampered["binding"]["signature"] = "A" * 86
        with self.assertRaisesRegex(NativeEgressError, "egress_retry_unauthorized"):
            self.controller.retry_ambiguous(binding, canonical_bytes(tampered))
        self.assertEqual(len(self.transport.calls), before)

    def test_shared_execution_fence_admits_one_identical_owner_retry(self) -> None:
        binding = self._admit("concurrent-retry")
        original = self.transport.send

        def initial_lost(request: dict[str, object]) -> bytes:
            original(request)
            raise TimeoutError()

        self.transport.send = initial_lost
        self.controller.advance_one(binding)
        authorization = self._signed_retry(binding)
        entered = threading.Event()
        release = threading.Event()

        def delayed(request: dict[str, object]) -> bytes:
            entered.set()
            self.assertTrue(release.wait(2))
            return original(request)

        self.transport.send = delayed
        results: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def run() -> None:
            try:
                results.append(self.controller.retry_ambiguous(binding, authorization))
            except BaseException as exception:
                errors.append(exception)

        first = threading.Thread(target=run)
        second = threading.Thread(target=run)
        first.start()
        self.assertTrue(entered.wait(2))
        second.start()
        release.set()
        first.join(2)
        second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual([row["state"] for row in results], ["confirmed", "confirmed"])
        self.assertEqual(len(self.transport.calls), 2)

    def test_worker_is_bounded_deterministic_and_never_performs_native_io(self) -> None:
        bindings = [
            self._admit(f"operation-{index}", bytes([index])) for index in range(3)
        ]
        status = self.controller.run_worker_batch(limit=2)
        self.assertEqual(status["processed"], 2)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(self.controller.inspect(bindings[0])["state"], "confirmed")
        self.assertEqual(self.controller.inspect(bindings[1])["state"], "confirmed")
        self.assertEqual(self.controller.inspect(bindings[2])["state"], "queued")
        bounded = self.controller.status()
        self.assertEqual(bounded["pending"], 1)
        self.assertNotIn("payload", json.dumps(bounded))
        self.assertNotIn("native-request", json.dumps(bounded))

    def test_daemon_worker_drains_echo_only_and_reports_lifecycle(self) -> None:
        binding = self._admit("operation-worker", b"worker-native-request")
        stop = threading.Event()
        self.controller.worker_started()
        worker = threading.Thread(
            target=_run_egress_worker,
            args=(self.controller, stop),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 2
        while self.controller.inspect(binding)["state"] != "confirmed":
            if time.monotonic() >= deadline:
                self.fail("visibility worker did not drain admitted echo")
            time.sleep(0.01)
        running = self.controller.status()
        self.assertEqual(running["worker_state"], "running")
        self.assertEqual(running["worker_failures"], 0)
        stop.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.controller.status()["worker_state"], "stopped")


class CatalogMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "migration.sqlite"
        with closing(sqlite3.connect(self.path)) as database:
            database.execute(
                "CREATE TABLE peer_outbox ("
                "request_id TEXT PRIMARY KEY, plan_sha256 TEXT NOT NULL, "
                "request BLOB NOT NULL, request_sha256 TEXT NOT NULL)"
            )

    def _controller(
        self, mode: Literal["validate", "migrate", "synthetic"]
    ) -> MandatoryEgressController:
        return MandatoryEgressController(
            policy=POLICY,
            proof_key=b"m" * 32,
            transport=TelegramTransport(),
            clock=lambda: 1_900_000_000_000,
            catalog_mode=mode,
        )

    def _resolve(self, locator: str) -> bytes:
        raise AssertionError(f"unexpected migration resolve: {locator}")

    def _authorize(self, binding: OperationBinding) -> bool:
        return False

    def _register(self, controller: MandatoryEgressController) -> None:
        controller.register_catalog(
            catalog_id="migration-catalog",
            path=self.path,
            resolve=self._resolve,
            authorize=self._authorize,
        )
        controller.register_path("peer-scope-request", "migration-catalog")

    def _tables(self) -> set[str]:
        with closing(sqlite3.connect(self.path)) as database:
            return {
                str(row[0])
                for row in database.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }

    def test_normal_registration_performs_zero_ddl_and_rejects_missing_schema(
        self,
    ) -> None:
        before = self._tables()
        with self.assertRaisesRegex(NativeEgressError, "egress_catalog_invalid"):
            self._register(self._controller("validate"))
        self.assertEqual(self._tables(), before)

    def test_unknown_migration_version_is_rejected_without_ddl(self) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        before = self._tables()
        with self.assertRaisesRegex(
            NativeEgressError, "egress_migration_not_authorized"
        ):
            migration.migrate_registered_catalogs(version=2)
        self.assertEqual(self._tables(), before)

    def test_explicit_migration_installs_then_normal_reopen_only_validates(
        self,
    ) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        self.assertNotIn("mandatory_egress_operations", self._tables())
        migration.migrate_registered_catalogs(version=1)
        installed = {
            "mandatory_egress_operations",
            "echo_v2_catalog",
            "echo_v2_obligations",
        }
        self.assertTrue(installed <= self._tables())
        before = self.path.read_bytes()
        migration.migrate_registered_catalogs(version=1)
        self.assertEqual(self.path.read_bytes(), before)
        self._register(self._controller("validate"))

    def test_preexisting_second_path_evidence_validates_during_ordered_registration(
        self,
    ) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        migration.register_path("peer-sync-request", "migration-catalog")
        migration.migrate_registered_catalogs(version=1)
        payload = b"historical-sync-request"
        operation_id = "00000000-0000-4000-8000-000000000139"
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO peer_outbox VALUES (?, ?, ?, ?)",
                (
                    operation_id,
                    "r" * 64,
                    payload,
                    hashlib.sha256(payload).hexdigest(),
                ),
            )
            migration.admit_in_transaction(
                database,
                catalog_id="migration-catalog",
                path_id="peer-sync-request",
                operation_id=operation_id,
                locator=operation_id,
                native_bytes=payload,
                projection=control_projection(operation_id),
                deadline_ms=1_900_000_060_000,
                authority_head="authority-head-1",
            )
            database.commit()

        validating = self._controller("validate")
        validating.register_catalog(
            catalog_id="migration-catalog",
            path=self.path,
            resolve=self._resolve,
            authorize=self._authorize,
        )
        validating.register_path("peer-scope-request", "migration-catalog")
        validating.register_path("peer-sync-request", "migration-catalog")
        validating.validate_registry({"peer-scope-request", "peer-sync-request"})

    def test_nonempty_historical_native_store_refuses_empty_journal_migration(
        self,
    ) -> None:
        payload = b"historical-peer-request"
        with closing(sqlite3.connect(self.path)) as database, database:
            database.execute(
                "INSERT INTO peer_outbox VALUES (?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000137",
                    "p" * 64,
                    payload,
                    hashlib.sha256(payload).hexdigest(),
                ),
            )
        before_tables = self._tables()
        migration = self._controller("migrate")
        self._register(migration)
        with self.assertRaisesRegex(
            NativeEgressError, "egress_historical_obligation_missing"
        ):
            migration.migrate_registered_catalogs(version=1)
        self.assertEqual(self._tables(), before_tables)

    def test_retry_reconciles_native_history_and_never_repairs_an_orphan(self) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        migration.migrate_registered_catalogs(version=1)
        payload = b"late-unjournaled-request"
        with closing(sqlite3.connect(self.path)) as database, database:
            database.execute(
                "INSERT INTO peer_outbox VALUES (?, ?, ?, ?)",
                (
                    "00000000-0000-4000-8000-000000000138",
                    "q" * 64,
                    payload,
                    hashlib.sha256(payload).hexdigest(),
                ),
            )
        before = self.path.read_bytes()
        with self.assertRaisesRegex(
            NativeEgressError, "egress_historical_obligation_missing"
        ):
            migration.migrate_registered_catalogs(version=1)
        self.assertEqual(self.path.read_bytes(), before)
        with self.assertRaisesRegex(
            NativeEgressError, "egress_historical_obligation_missing"
        ):
            self._register(self._controller("validate"))

    def test_additional_visibility_schema_is_rejected_without_mutation(self) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        migration.migrate_registered_catalogs(version=1)
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("CREATE TABLE mandatory_egress_shadow (value TEXT)")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(NativeEgressError, "egress_catalog_invalid"):
            self._register(self._controller("validate"))
        self.assertEqual(self.path.read_bytes(), before)

    def test_partial_schema_loss_is_rejected_without_repair(self) -> None:
        migration = self._controller("migrate")
        self._register(migration)
        migration.migrate_registered_catalogs(version=1)
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("DROP TABLE echo_v2_obligations")
        before = self._tables()
        with self.assertRaisesRegex(NativeEgressError, "egress_catalog_invalid"):
            self._register(self._controller("validate"))
        self.assertEqual(self._tables(), before)
        self.assertNotIn("echo_v2_obligations", self._tables())


if __name__ == "__main__":
    unittest.main()
