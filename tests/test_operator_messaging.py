"""Provisioning negative controls and operator entrypoint; no live enrollment."""

import contextlib
import copy
import hashlib
import io
import json
import os
import sqlite3
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.messaging_config import (
    BINDING_DOMAIN,
    _public_identity,
    config_digest,
    create_binding,
    load_application,
    read_publication,
)
from daimon_matrix.native_egress import synthetic_visibility
from daimon_matrix.operator_messaging import prepare
from tests.test_messaging_runtime import application_fixture


def signed_visibility_installation(root: Path, runtime, pair, app_root: Path) -> Path:
    application, _metadata = read_publication(runtime, app_root)
    application_sha256 = config_digest(application)
    token = b"137:SIGNED_TEST_ONLY"
    proof_key = b"\x89" * 32
    for name, raw in (("telegram.token", token), ("echo-proof.key", proof_key)):
        path = root / name
        path.write_bytes(raw)
        path.chmod(0o600)
    participants = sorted({pair.sender.state.being_ref, pair.recipient.state.being_ref})
    scope = {
        "mode": "all-inter-daimon-communications",
        "channels": [
            {
                "channel_id": application[direction]["channel_id"],
                "direction": direction,
                "local_being_ref": pair.sender.state.being_ref,
                "peer_being_ref": pair.recipient.state.being_ref,
                "bootstrap_policy": {},
                "relationship_disclosure": {},
            }
            for direction in ("incoming", "outgoing")
        ],
        "projected_content": "complete-plaintext-content-and-metadata",
    }
    disclosure = {
        "schema": "dm.messaging.visibility-disclosure/v1",
        "issued_at_ms": runtime.service.clock(),
        "destination": {
            "bot_id": 137,
            "chat_id": -100137,
            "topic_id": None,
            "representation": "plain-json/v2",
        },
        "scope": scope,
        "scope_sha256": hashlib.sha256(canonical_bytes(scope)).hexdigest(),
        "participants": participants,
        "risk": (
            "all-inter-daimon-communication-will-be-posted-as-plaintext-"
            "to-the-fixed-telegram-destination"
        ),
    }

    def peer_binding(document):
        identity = _public_identity(
            pair.recipient.authority,
            pair.recipient.origin,
            "peer-visibility-runtime",
            "peer-visibility-runtime",
            runtime.service.clock(),
        )
        body = {**identity, "application_sha256": config_digest(document)}
        signature = Ed25519PrivateKey.from_private_bytes(
            pair.recipient.signer.seed
        ).sign(BINDING_DOMAIN + canonical_bytes(body))
        return {
            "schema": "dm.messaging.operator-binding/v1",
            "body": body,
            "signature": b64url(signature),
        }

    owner_ref = runtime.service.ledger.authority.manifest.being_ref
    bindings = {
        owner_ref: create_binding(runtime, disclosure),
        pair.recipient.state.being_ref: peer_binding(disclosure),
    }
    acceptance_set = {
        "schema": "dm.messaging.visibility-acceptance-set/v1",
        "disclosure_sha256": config_digest(disclosure),
        "bindings": [bindings[participant] for participant in participants],
    }
    document = {
        "schema": "dm.messaging.visibility-installation/v1",
        "generation": 1,
        "runtime_id": runtime.service.runtime_id,
        "application_sha256": application_sha256,
        "disclosure": disclosure,
        "acceptance_set": acceptance_set,
        "policy": {
            "schema": "daimon-visibility-policy/v2",
            "generation": 1,
            "origin": "owner-signed-installation",
            "bot_id": 137,
            "chat_id": -100137,
            "topic_id": None,
            "representation": "plain-json/v2",
            "acceptance_digest": config_digest(acceptance_set),
            "proof_key_id": "sha256:" + hashlib.sha256(proof_key).hexdigest(),
        },
        "secrets": {
            "telegram_token_file": "telegram.token",
            "telegram_token_sha256": hashlib.sha256(token).hexdigest(),
            "proof_key_file": "echo-proof.key",
        },
        "telegram_qualification": {
            "schema": "dm.messaging.telegram-qualification/v1",
            "qualified_at_ms": runtime.service.clock(),
            "token_sha256": hashlib.sha256(token).hexdigest(),
            "get_me_bot_id": 137,
            "probe_chat_id": -100137,
            "probe_topic_id": None,
            "probe_message_id": 1,
            "probe_text_sha256": "b" * 64,
        },
    }
    installation = root / "visibility-installation.json"
    installation.write_bytes(
        canonical_bytes(
            {"document": document, "binding": create_binding(runtime, document)}
        )
    )
    installation.chmod(0o600)
    return installation


class ProvisioningTests(unittest.TestCase):
    def test_host_visibility_uses_signed_application_not_runtime_digest(self):
        from daimon_matrix.operator_messaging import host_visibility_factory
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "host-app"
        prepare(runtime, target, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        factory = host_visibility_factory(
            target, installation, clock=lambda: self.pair.now
        )
        restarted = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress_factory=factory,
        )
        self.assertTrue(restarted.egress.release_enabled)
        self.assertEqual(restarted.egress.catalog_mode, "validate")
        composed = load_application(restarted, target)
        self.assertIs(composed.egress, restarted.egress)

        # Signed publication verification, not merely a matching app digest.
        publication = target / "publication.json"
        value = json.loads(publication.read_bytes())
        value["binding"]["signature"] = "tampered"
        publication.write_bytes(canonical_bytes(value))
        with self.assertRaises(ValueError):
            load_runtime(
                runtime.state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: self.pair.now,
                egress_factory=factory,
            )

    @contextlib.contextmanager
    def interrupt_capability_entry_publication(self, operator, final_path, boundary):
        real_write = operator.os.write
        real_fsync = operator.os.fsync
        real_publish = operator._publish
        real_sync = operator._sync
        interrupted = False

        def descriptor_path(descriptor):
            try:
                return os.path.realpath(f"/proc/self/fd/{descriptor}")
            except OSError:
                return ""

        def is_staging_descriptor(descriptor):
            path = descriptor_path(descriptor)
            return path == str(final_path) or path.startswith(
                str(final_path) + ".stage-"
            )

        def interrupt_write(descriptor, raw):
            nonlocal interrupted
            if boundary == "after_prefix_write" and is_staging_descriptor(descriptor):
                interrupted = True
                written = real_write(descriptor, raw[:1])
                raise OSError(f"synthetic {boundary} after {written} byte")
            return real_write(descriptor, raw)

        def interrupt_fsync(descriptor):
            nonlocal interrupted
            if boundary == "after_file_fsync" and is_staging_descriptor(descriptor):
                real_fsync(descriptor)
                interrupted = True
                raise OSError(f"synthetic {boundary}")
            return real_fsync(descriptor)

        def interrupt_publish(staging, target):
            nonlocal interrupted
            real_publish(staging, target)
            if boundary == "after_no_replace_install" and target == final_path:
                interrupted = True
                raise SystemExit(f"synthetic {boundary}")

        def interrupt_sync(path):
            nonlocal interrupted
            if path == final_path.parent and final_path.exists():
                if boundary == "before_directory_fsync":
                    interrupted = True
                    raise OSError(f"synthetic {boundary}")
                if boundary == "after_directory_fsync":
                    real_sync(path)
                    interrupted = True
                    raise OSError(f"synthetic {boundary}")
            return real_sync(path)

        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    patch.object(operator.os, "write", side_effect=interrupt_write)
                )
                stack.enter_context(
                    patch.object(operator.os, "fsync", side_effect=interrupt_fsync)
                )
                stack.enter_context(
                    patch.object(operator, "_publish", side_effect=interrupt_publish)
                )
                stack.enter_context(
                    patch.object(operator, "_sync", side_effect=interrupt_sync)
                )
                yield
        finally:
            self.assertTrue(interrupted, f"boundary was not reached: {boundary}")

    def test_revocation_journal_publication_is_atomic_and_retry_converges(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import (
            _capability_journal_names,
            read_publication,
        )
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        boundaries = (
            "after_prefix_write",
            "after_file_fsync",
            "after_no_replace_install",
            "before_directory_fsync",
            "after_directory_fsync",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                runtime, spec, sources, _ = application_fixture(self)
                target = self.root / ("atomic-revoke-" + boundary)
                receipt = prepare(runtime, target, spec, secret_sources=sources)
                application, _ = read_publication(runtime, target)
                _, stem = _capability_journal_names(
                    runtime, application["client"]["descriptor"]
                )
                final_path = runtime.state_root / (stem + "-00000000000000000001.json")

                with (
                    self.interrupt_capability_entry_publication(
                        operator, final_path, boundary
                    ),
                    self.assertRaises(
                        SystemExit
                        if boundary == "after_no_replace_install"
                        else ValueError
                    ),
                ):
                    operator.revoke_capability(
                        runtime,
                        target,
                        expected_application_sha256=receipt["application_sha256"],
                    )

                if final_path.exists():
                    raw = final_path.read_bytes()
                    self.assertEqual(canonical_bytes(json.loads(raw)), raw)
                restarted = load_runtime(
                    runtime.state_root,
                    "runtime.json",
                    lambda: bytearray(PASSWORD),
                    clock=lambda: self.pair.now,
                    egress=synthetic_visibility(clock=lambda: self.pair.now),
                )
                result = operator.revoke_capability(
                    restarted,
                    target,
                    expected_application_sha256=receipt["application_sha256"],
                )
                self.assertEqual(result["status"], "revoked")
                self.assertEqual(result["sequence"], 1)
                self.assertEqual(
                    list(runtime.state_root.glob(final_path.name + ".stage-*")), []
                )
                with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
                    load_application(restarted, target)

    def test_replacement_journal_publication_is_atomic_and_recovery_converges(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import (
            _capability_journal_names,
            config_digest,
            read_publication,
        )
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        boundaries = (
            "after_prefix_write",
            "after_file_fsync",
            "after_no_replace_install",
            "before_directory_fsync",
            "after_directory_fsync",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                runtime, spec, sources, _ = application_fixture(self)
                target = self.root / ("atomic-replace-" + boundary)
                receipt = prepare(runtime, target, spec, secret_sources=sources)
                initial, _ = read_publication(runtime, target)
                _, stem = _capability_journal_names(
                    runtime, initial["client"]["descriptor"]
                )
                final_path = runtime.state_root / (stem + "-00000000000000000001.json")
                self.pair.now += 1

                with (
                    self.interrupt_capability_entry_publication(
                        operator, final_path, boundary
                    ),
                    self.assertRaises(
                        SystemExit
                        if boundary == "after_no_replace_install"
                        else ValueError
                    ),
                ):
                    operator.renew(
                        runtime,
                        target,
                        expected_application_sha256=receipt["application_sha256"],
                    )

                current, _ = read_publication(runtime, target)
                current_digest = config_digest(current)
                self.assertNotEqual(current_digest, receipt["application_sha256"])
                if final_path.exists():
                    raw = final_path.read_bytes()
                    self.assertEqual(canonical_bytes(json.loads(raw)), raw)
                restarted = load_runtime(
                    runtime.state_root,
                    "runtime.json",
                    lambda: bytearray(PASSWORD),
                    clock=lambda: self.pair.now,
                    egress=synthetic_visibility(clock=lambda: self.pair.now),
                )
                result = operator.recover(
                    restarted,
                    target,
                    expected_application_sha256=current_digest,
                )
                self.assertEqual(result["status"], "configured")
                self.assertEqual(
                    list(runtime.state_root.glob(final_path.name + ".stage-*")), []
                )
                loaded = load_application(restarted, target)
                self.assertIn(
                    current["client"]["descriptor"]["capability_id"],
                    loaded.service.capabilities,
                )

    def test_genesis_journal_publication_is_atomic_and_exact_retry_converges(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.local_api import create_messaging_capability
        from daimon_matrix.messaging_config import _capability_journal_names
        from daimon_matrix.service import MESSAGING_METHODS

        boundaries = (
            "after_prefix_write",
            "after_file_fsync",
            "after_no_replace_install",
            "before_directory_fsync",
            "after_directory_fsync",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                runtime, spec, sources, _ = application_fixture(self)
                target = self.root / ("atomic-genesis-" + boundary)
                key = b"g" * 32
                client_token = "c" * 32
                descriptor = create_messaging_capability(
                    key,
                    client_id="client:messaging:" + client_token,
                    methods=sorted(MESSAGING_METHODS),
                    not_before_ms=self.pair.now,
                ).descriptor
                _, stem = _capability_journal_names(runtime, descriptor)
                final_path = runtime.state_root / (stem + "-00000000000000000000.json")

                with (
                    patch.object(operator.secrets, "token_bytes", return_value=key),
                    patch.object(
                        operator.secrets,
                        "token_hex",
                        side_effect=lambda count: "c" * (count * 2),
                    ),
                    self.interrupt_capability_entry_publication(
                        operator, final_path, boundary
                    ),
                    self.assertRaises(
                        SystemExit
                        if boundary == "after_no_replace_install"
                        else ValueError
                    ),
                ):
                    operator.prepare(runtime, target, spec, secret_sources=sources)

                self.assertFalse(target.exists())
                if final_path.exists():
                    raw = final_path.read_bytes()
                    self.assertEqual(canonical_bytes(json.loads(raw)), raw)
                with (
                    patch.object(operator.secrets, "token_bytes", return_value=key),
                    patch.object(
                        operator.secrets,
                        "token_hex",
                        side_effect=lambda count: "c" * (count * 2),
                    ),
                ):
                    result = operator.prepare(
                        runtime, target, spec, secret_sources=sources
                    )
                self.assertEqual(result["status"], "configured")
                self.assertEqual(result["capability_id"], descriptor["capability_id"])
                self.assertEqual(
                    list(runtime.state_root.glob(final_path.name + ".stage-*")), []
                )
                self.assertIsNotNone(
                    load_application(runtime, target).service.messaging
                )

    def test_journal_conflicts_and_unsafe_or_unbounded_residue_are_never_deleted(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import (
            _capability_journal_names,
            read_publication,
        )

        def prepared(label):
            runtime, spec, sources, _ = application_fixture(self)
            target = self.root / label
            receipt = prepare(runtime, target, spec, secret_sources=sources)
            application, _ = read_publication(runtime, target)
            _, stem = _capability_journal_names(
                runtime, application["client"]["descriptor"]
            )
            final_path = runtime.state_root / (stem + "-00000000000000000001.json")
            return runtime, target, receipt, final_path

        runtime, target, receipt, final_path = prepared("conflicting-final")
        conflict = b"installed-conflict"
        final_path.write_bytes(conflict)
        final_path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "messaging_capability_state_rejected"):
            operator.revoke_capability(
                runtime,
                target,
                expected_application_sha256=receipt["application_sha256"],
            )
        self.assertEqual(final_path.read_bytes(), conflict)

        residue_cases = (("unsafe", 1), ("malformed", 1), ("unbounded", 9))
        for case, count in residue_cases:
            with self.subTest(case=case):
                runtime, target, receipt, final_path = prepared("residue-" + case)
                if case == "malformed":
                    residues = [
                        final_path.with_name(final_path.name + ".stage-not-a-token")
                    ]
                else:
                    residues = [
                        final_path.with_name(final_path.name + f".stage-{index:032x}")
                        for index in range(count)
                    ]
                for residue in residues:
                    residue.write_bytes(b"owned-stage-residue")
                    residue.chmod(0o600)
                if case == "unsafe":
                    residues[0].chmod(0o640)
                with self.assertRaisesRegex(
                    ValueError, "messaging_capability_state_rejected"
                ):
                    operator.revoke_capability(
                        runtime,
                        target,
                        expected_application_sha256=receipt["application_sha256"],
                    )
                self.assertFalse(final_path.exists())
                self.assertTrue(all(path.exists() for path in residues))

    def test_prepare_publishes_until_revoked_v2_capability_across_clock_advance(self):
        from daimon_matrix.messaging_config import load_application

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "v2-capability"
        result = prepare(runtime, target, spec, secret_sources=sources)
        application = load_application(runtime, target)
        capability = application.service.capabilities[result["capability_id"]]
        self.assertEqual(capability.descriptor["schema"], "dm.local.capability/v2")
        self.assertEqual(
            capability.descriptor["validity"],
            {"mode": "until-revoked", "not_before_ms": self.pair.now},
        )
        restarted = load_application(runtime, target)
        self.pair.now += 10**12
        self.assertTrue(
            restarted.service.capabilities[result["capability_id"]].active_at(
                self.pair.now
            )
        )

    def test_authenticated_capability_revocation_survives_restart(self):
        from daimon_matrix.operator_messaging import revoke_capability
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "revoked-capability"
        result = prepare(runtime, target, spec, secret_sources=sources)
        journal_before = sorted(runtime.state_root.glob(".messaging-capability-*.json"))
        self.assertGreaterEqual(len(journal_before), 2)
        revoked = revoke_capability(
            runtime,
            target,
            expected_application_sha256=result["application_sha256"],
        )
        self.assertEqual(revoked["status"], "revoked")
        with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
            load_application(runtime, target)
        restarted = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress=synthetic_visibility(clock=lambda: self.pair.now),
        )
        with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
            load_application(restarted, target)

    def test_interrupted_revocation_resumes_forward_and_remains_irreversible(self):
        from pathlib import Path

        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import (
            _capability_journal_names,
            read_publication,
        )
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "interrupted-revocation"
        result = prepare(runtime, target, spec, secret_sources=sources)
        application, _ = read_publication(runtime, target)
        _, stem = _capability_journal_names(
            runtime, application["client"]["descriptor"]
        )
        pointer = runtime.state_root / (stem + "-current.json")
        replace = operator.os.replace

        def interrupt_current_pointer(source, destination):
            if Path(destination) == pointer:
                raise OSError("synthetic revocation-pointer interruption")
            replace(source, destination)

        with (
            patch.object(operator.os, "replace", side_effect=interrupt_current_pointer),
            self.assertRaisesRegex(
                ValueError, "messaging_capability_revocation_rejected"
            ),
        ):
            operator.revoke_capability(
                runtime,
                target,
                expected_application_sha256=result["application_sha256"],
            )
        with self.assertRaisesRegex(ValueError, "messaging_capability_state_rejected"):
            load_application(runtime, target)

        restarted = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress=synthetic_visibility(clock=lambda: self.pair.now),
        )
        resumed = operator.revoke_capability(
            restarted,
            target,
            expected_application_sha256=result["application_sha256"],
        )

        self.assertEqual(resumed["status"], "revoked")
        with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
            load_application(restarted, target)
        self.pair.now += 1
        with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
            operator.renew(
                restarted,
                target,
                expected_application_sha256=result["application_sha256"],
            )

    def test_loaded_service_rechecks_capability_state_before_fresh_request(self):
        from daimon_matrix.local_api import LocalApiError, create_request
        from daimon_matrix.operator_messaging import revoke_capability
        from daimon_matrix.synthetic_relationships import _uuid

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "live-revocation"
        result = prepare(runtime, target, spec, secret_sources=sources)
        application = load_application(runtime, target)
        capability = application.service.capabilities[result["capability_id"]]
        request = create_request(
            capability,
            request_id=_uuid("live-capability-revocation"),
            issued_at_ms=self.pair.now,
            method="messaging.inbox",
            params={"channel_id": "peer-in", "after": 0, "limit": 1},
        )
        revoke_capability(
            runtime,
            target,
            expected_application_sha256=result["application_sha256"],
        )
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            application.service.handle(request)

    def test_capability_state_rejects_rolled_back_high_water_pointer(self):
        from daimon_matrix.messaging_config import read_document
        from daimon_matrix.operator_messaging import revoke_capability

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "rolled-back-capability"
        result = prepare(runtime, target, spec, secret_sources=sources)
        descriptor = read_document(target / "application.json")["client"]["descriptor"]
        from daimon_matrix.messaging_config import _capability_journal_names

        _, stem = _capability_journal_names(runtime, descriptor)
        pointer = runtime.state_root / (stem + "-current.json")
        active_bytes = pointer.read_bytes()
        revoke_capability(
            runtime,
            target,
            expected_application_sha256=result["application_sha256"],
        )
        pointer.write_bytes(active_bytes)
        with self.assertRaisesRegex(ValueError, "messaging_capability_state_rejected"):
            load_application(runtime, target)

    def test_capability_state_rejects_entry_and_pointer_rollback_against_floor(self):
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.operator_messaging import prepare, revoke_capability

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "capability-floor-rollback"
        result = prepare(runtime, target, spec, secret_sources=sources)
        state_files = sorted(
            runtime.state_root.glob(".messaging-capability-*-00000000000000000000.json")
        )
        self.assertEqual(len(state_files), 1)
        genesis = state_files[0].read_bytes()
        current = next(
            path
            for path in runtime.state_root.glob(".messaging-capability-*-current.json")
        )
        revoke_capability(
            runtime,
            target,
            expected_application_sha256=result["application_sha256"],
        )
        latest = next(
            path
            for path in runtime.state_root.glob(
                ".messaging-capability-*-00000000000000000001.json"
            )
        )
        latest.unlink()
        current.write_bytes(genesis)
        current.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "messaging_capability_state_rejected"):
            load_application(runtime, target)

    def test_renew_rotates_v2_capability_and_rejects_old_publication_replay(self):
        import shutil

        from daimon_matrix.messaging_config import config_digest, read_document
        from daimon_matrix.operator_messaging import renew

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "renew-current"
        replay = self.root / "renew-replay"
        prepare(runtime, target, spec, secret_sources=sources)
        old_application = read_document(target / "application.json")
        old_capability_id = old_application["client"]["descriptor"]["capability_id"]
        shutil.copytree(target, replay)
        self.pair.now += 1
        result = renew(
            runtime,
            target,
            expected_application_sha256=config_digest(old_application),
        )
        current = read_document(
            target / result["client_config"].split("/")[0] / "application.json"
        )
        self.assertEqual(
            current["client"]["descriptor"]["schema"], "dm.local.capability/v2"
        )
        self.assertNotEqual(
            current["client"]["descriptor"]["capability_id"], old_capability_id
        )
        load_application(runtime, target)
        with self.assertRaisesRegex(ValueError, "messaging_capability_stale"):
            load_application(runtime, replay)

    def test_v2_permissions_survive_restart_and_large_clock_for_full_messaging_path(
        self,
    ):
        import tempfile
        import threading
        from pathlib import Path

        from daimon_matrix import relationships
        from daimon_matrix.canonical import b64url
        from daimon_matrix.daemon import create_messaging_http_server
        from daimon_matrix.ledger import Ledger
        from daimon_matrix.messaging import (
            GrantReference,
            MessagingChannel,
            MessagingPeerPolicy,
        )
        from daimon_matrix.messaging_config import load_application
        from daimon_matrix.messaging_store import MessagingInboxStore
        from daimon_matrix.native_egress import synthetic_visibility
        from daimon_matrix.operator_messaging import prepare
        from daimon_matrix.routes import OpaqueInbox, TransportIngress
        from daimon_matrix.runtime import load_runtime
        from daimon_matrix.synthetic_relationships import (
            NOW,
            _event_ref,
            _Journey,
            _seed,
            _uuid,
        )
        from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
        from tests.test_issue136_permissions import V2Journey
        from tests.test_messaging_runtime import (
            application_fixture,
            loaded,
            public_document,
        )
        from tests.test_native_messaging import synthetic_sender

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        journey_root = Path(temporary.name) / "v2-journey"
        journey = V2Journey(journey_root)
        journey.prepare()
        _, spec, sources, _ = application_fixture(self)
        runtime_fixture = RuntimeFixture()
        self.addCleanup(runtime_fixture.doCleanups)
        _, runtime, _ = loaded(runtime_fixture, journey.identities["founder"])
        runtime = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress=synthetic_visibility(clock=lambda: self.pair.now),
        )

        forward = next(
            event
            for event in journey.store.events()
            if event["kind"] == "matrix/relationship-grant"
        )
        permission = {
            **forward["payload"]["permissions"][0],
            "delegable": False,
            "remaining_delegation_depth": 0,
        }
        nonce = b64url(_seed("reverse-grant"))
        reverse_id = relationships.grant_id(
            nonce=nonce,
            relationship=forward["payload"]["relationship_id"],
            grantor_being_ref=journey.identities["member"].state.being_ref,
            subject_being_ref=journey.identities["founder"].state.being_ref,
        )
        reverse = _Journey.append(
            journey,
            "member",
            "matrix/relationship-grant",
            {
                "schema": "dm.relationship.grant/v2",
                "grant_id": reverse_id,
                "nonce": nonce,
                "relationship_id": forward["payload"]["relationship_id"],
                "tribe_ref": forward["payload"]["tribe_ref"],
                "grantor_being_ref": journey.identities["member"].state.being_ref,
                "subject_being_ref": journey.identities["founder"].state.being_ref,
                "permissions": [permission],
                "validity": {"mode": "until-revoked", "not_before_ms": NOW},
                "issued_at_ms": NOW + 8,
                "parent_grant_ref": _event_ref(forward),
                "delegation_sequence": 0,
                "previous_delegation_event_id": None,
            },
            at_ms=NOW + 8,
        )
        _Journey.append(
            journey,
            "founder",
            "matrix/relationship-grant-acceptance",
            {
                "schema": "dm.relationship.grant-acceptance/v2",
                "grant_id": reverse_id,
                "grant_ref": _event_ref(reverse),
                "relationship_id": forward["payload"]["relationship_id"],
                "grantor_being_ref": journey.identities["member"].state.being_ref,
                "subject_being_ref": journey.identities["founder"].state.being_ref,
                "accepted_at_ms": NOW + 9,
            },
            at_ms=NOW + 9,
        )
        snapshot = journey.store.view(
            at_ms=NOW + 10, card_verifier=journey.card_verifier
        ).snapshot(forward["payload"]["tribe_ref"])
        memberships = {
            row["principal_id"]: row["membership_ref"]
            for row in snapshot.value["members"]
        }
        founder = journey.identities["founder"]
        member = journey.identities["member"]
        forward_policy = {
            **spec["outgoing"]["policy"],
            "peer_being_ref": founder.state.being_ref,
            "peer_embodiment_id": founder.origin["embodiment_id"],
            "peer_credential_id": founder.credential["artifact_id"],
            "relationship_id": forward["payload"]["relationship_id"],
            "tribe_ref": forward["payload"]["tribe_ref"],
            "membership_ref": memberships[member.state.being_ref],
            "resource_ref": permission["resource_ref"],
            "operation": permission["operations"][0],
            "grant_refs": [
                {
                    "grant_id": forward["payload"]["grant_id"],
                    "event_id": forward["event_id"],
                    "event_hash": forward["content_hash"],
                }
            ],
        }
        reverse_policy = {
            **spec["incoming"]["policy"],
            "peer_being_ref": member.state.being_ref,
            "peer_embodiment_id": member.origin["embodiment_id"],
            "peer_credential_id": member.credential["artifact_id"],
            "relationship_id": forward["payload"]["relationship_id"],
            "tribe_ref": forward["payload"]["tribe_ref"],
            "membership_ref": memberships[founder.state.being_ref],
            "resource_ref": permission["resource_ref"],
            "operation": permission["operations"][0],
            "grant_refs": [
                {
                    "grant_id": reverse["payload"]["grant_id"],
                    "event_id": reverse["event_id"],
                    "event_hash": reverse["content_hash"],
                }
            ],
        }
        spec["authorities"] = [
            public_document(journey.identities[label], label)
            for label in ("founder", "member", "delegate")
        ]
        spec["relationship_events"] = journey.store.events()
        spec["incoming"].update(
            recipient_being_ref=founder.state.being_ref,
            recipient_credential_id=founder.credential["artifact_id"],
            policy=reverse_policy,
        )
        spec["outgoing"].update(
            recipient_being_ref=member.state.being_ref,
            recipient_credential_id=member.credential["artifact_id"],
            policy=forward_policy,
        )

        def parsed_policy(value):
            fields = dict(value)
            fields["grant_refs"] = tuple(
                GrantReference(**reference) for reference in fields["grant_refs"]
            )
            return MessagingPeerPolicy(**fields)

        receiver = MessagingChannel(
            policy=parsed_policy(forward_policy),
            local_being_ref=member.state.being_ref,
            local_credential_id=member.credential["artifact_id"],
            authority_resolver=lambda ref: journey.authorities[ref],
            relationships=journey.store,
            custody=journey.custody("member"),
            inbox=MessagingInboxStore(self.root / "v2-recipient-inbox.sqlite"),
            clock=lambda: self.pair.now,
        )
        ingresses = {}
        receiver_egress = synthetic_visibility(clock=lambda: self.pair.now)
        for phase in ("evidence", "message"):
            route = spec["outgoing"]["routes"][phase]
            ingresses[phase] = TransportIngress(
                **{key: route[key] for key in ("provider_ref", "route_ref", "key_ref")},
                secret=sources[route["secret_file"]].read_bytes(),
                recipient_id=forward_policy["membership_ref"],
                recipient_body_ref=member.origin["body_ref"],
                recipient_embodiment_id=member.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / ("v2-http-" + phase + ".sqlite"),
                    clock=lambda: self.pair.now,
                ),
                clock=lambda: self.pair.now,
                egress=receiver_egress,
                egress_catalog_id=f"test-v2-http-{phase}-responses",
                intake_validator=getattr(receiver, "receive_" + phase),
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
            target = self.root / "v2-clock-application"
            receipt = prepare(runtime, target, spec, secret_sources=sources)
            restarted = load_runtime(
                runtime.state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: self.pair.now,
                egress=synthetic_visibility(clock=lambda: self.pair.now),
            )
            app = load_application(restarted, target)
            # Runtime/session capabilities remain finite.  Only after restart and
            # application composition do we advance the messaging clock to prove
            # that the V2 messaging permission itself is valid until revocation.
            self.pair.now += 10**12
            capability = app.service.capabilities[receipt["capability_id"]]
            self.assertTrue(capability.active_at(self.pair.now))
            delivery = app.service.messaging.deliveries["peer-out"]
            delivered = delivery.send(
                client_id=capability.client_id,
                send_id=_uuid("v2-large-clock-delivery"),
                thread_id=_uuid("v2-large-clock-thread"),
                text="survives a large clock advance",
            )
            self.assertEqual(delivered["transport_status"], "recipient-intake")
            incoming = receiver.page(after=0, limit=1)[0]["message"]
            self.assertEqual(
                incoming["payload"]["body"]["text"],
                "survives a large clock advance",
            )
            reverse_context = MessagingChannel(
                policy=parsed_policy(reverse_policy),
                local_being_ref=founder.state.being_ref,
                local_credential_id=founder.credential["artifact_id"],
                authority_resolver=lambda ref: journey.authorities[ref],
                relationships=journey.store,
                custody=journey.custody("member"),
                inbox=MessagingInboxStore(self.root / "v2-reply-context.sqlite"),
                clock=lambda: self.pair.now,
            )
            member_ledger = Ledger(
                self.root / "v2-member-ledger.sqlite",
                authority=member.authority,
                local_origin=member.origin,
                clock=lambda: self.pair.now,
            )
            member_ledger.initialize()
            reply_sender = synthetic_sender(
                context=reverse_context,
                ledger=member_ledger,
                signer=member.signer,
                delivery_custody=journey.custody("member"),
                outbox_path=self.root / "v2-reply-outbox.sqlite",
                clock=lambda: self.pair.now,
                catalog_id="test-v2-reply-messaging-outbox",
            )
            reply_pair = reply_sender.prepare(
                client_id="client:v2-reply",
                send_id=_uuid("v2-large-clock-reply"),
                thread_id=incoming["payload"]["intent"]["thread_id"],
                text="reply also survives",
                response_to=(receiver, incoming["event_id"]),
            )
            app_incoming = app.service.messaging.channels["peer-in"]
            app_incoming.receive_evidence(reply_pair[0])
            app_incoming.receive_message(reply_pair[1])
            self.assertEqual(
                app_incoming.page(after=0, limit=1)[0]["message"]["payload"]["body"][
                    "text"
                ],
                "reply also survives",
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_v2_migration_requires_finishing_v1_authoring(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_publication
        from daimon_matrix.synthetic_relationships import _uuid

        runtime, spec, sources, _ = application_fixture(self)
        spec["outgoing"]["policy"]["max_ttl_ms"] = 1
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        application = load_application(runtime, target)
        sender = application.service.messaging.deliveries["peer-out"].sender
        logical_send_id = _uuid("pre-migration")
        thread_id = _uuid("migration-thread")
        with (
            patch.object(
                sender.ledger,
                "append_local_idempotent",
                side_effect=OSError("interrupted authoring"),
            ),
            self.assertRaises(OSError),
        ):
            sender.prepare(
                client_id="client:operator-messaging",
                send_id=logical_send_id,
                thread_id=thread_id,
                text="reserved",
            )
        previous, _ = read_publication(runtime, target)
        with self.assertRaisesRegex(
            ValueError, "messaging_semantic_migration_drain_required"
        ):
            operator.upgrade_semantic_receipts(
                runtime, target, expected_application_sha256=config_digest(previous)
            )
        self.assertFalse(runtime.service.communication.receipts_v2)
        self.pair.now += sender.context.policy.max_ttl_ms
        operator.upgrade_semantic_receipts(
            runtime, target, expected_application_sha256=config_digest(previous)
        )
        fresh = sender.prepare(
            client_id="client:operator-messaging",
            send_id=logical_send_id,
            thread_id=thread_id,
            text="reserved",
        )
        self.assertEqual(
            sender.prepare(
                client_id="client:operator-messaging",
                send_id=logical_send_id,
                thread_id=thread_id,
                text="reserved",
            ),
            fresh,
        )
        with contextlib.closing(sqlite3.connect(sender.outbox.path)) as database:
            rows = database.execute(
                "SELECT send_id, plan, evidence, message FROM messaging_outbox "
                "ORDER BY rowid"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        first_plan, fresh_plan = (json.loads(row[1]) for row in rows)
        self.assertEqual(rows[0][0], logical_send_id)
        self.assertNotEqual(rows[1][0], logical_send_id)
        self.assertEqual(rows[0][2:], (None, None))
        self.assertEqual(rows[1][2:], fresh)
        self.assertEqual(
            [first_plan["carrier_generation"], fresh_plan["carrier_generation"]],
            [1, 2],
        )
        self.assertEqual(
            [first_plan["logical_send_id"], fresh_plan["logical_send_id"]],
            [logical_send_id, logical_send_id],
        )
        self.assertEqual(fresh_plan["issued_at_ms"], first_plan["expires_at_ms"])
        self.assertEqual(
            fresh_plan["expires_at_ms"],
            fresh_plan["issued_at_ms"] + sender.context.policy.max_ttl_ms,
        )
        self.assertNotEqual(
            first_plan["message_authorization_id"],
            fresh_plan["message_authorization_id"],
        )
        self.assertNotEqual(
            first_plan["evidence_authorization_id"],
            fresh_plan["evidence_authorization_id"],
        )
        message = sender.ledger.event(json.loads(fresh[1])["event_id"])
        assert message is not None
        self.assertEqual(message["payload"]["body"]["text"], "reserved")
        self.assertIsNone(message["payload"]["reply"])

    def test_v2_migration_restart_before_publication_selection(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_publication
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        previous, _ = read_publication(runtime, target)
        digest = config_digest(previous)
        anchor = runtime.service.communication.anchor_path.read_bytes()
        original = operator._compose

        def crash(*args, **kwargs):
            if args[2]["schema"] == "dm.messaging.application/v2":
                raise OSError("crash before selection")
            return original(*args, **kwargs)

        with (
            patch.object(operator, "_compose", side_effect=crash),
            self.assertRaises(OSError),
        ):
            operator.upgrade_semantic_receipts(
                runtime, target, expected_application_sha256=digest
            )
        self.assertEqual(anchor, runtime.service.communication.anchor_path.read_bytes())
        restarted = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress=synthetic_visibility(clock=lambda: self.pair.now),
        )
        self.assertTrue(restarted.service.communication.receipts_v2)
        with self.assertRaises(ValueError):
            load_application(restarted, target)
        operator.upgrade_semantic_receipts(
            restarted, target, expected_application_sha256=digest
        )
        again = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress=synthetic_visibility(clock=lambda: self.pair.now),
        )
        self.assertIsNotNone(load_application(again, target).service.messaging)

    def test_explicit_v2_successor_preserves_stores_and_retries(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_publication

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        previous, _ = read_publication(runtime, target)
        before = {
            name: (target / name).read_bytes() for name in spec["stores"].values()
        }
        result = operator.upgrade_semantic_receipts(
            runtime, target, expected_application_sha256=config_digest(previous)
        )
        loaded = load_application(runtime, target)
        self.assertIsNotNone(
            loaded.service.messaging.deliveries["peer-out"].sender.communication
        )
        self.assertEqual(
            before, {name: (target / name).read_bytes() for name in before}
        )
        self.assertEqual(
            result,
            operator.upgrade_semantic_receipts(
                runtime, target, expected_application_sha256=config_digest(previous)
            ),
        )
        with self.assertRaises(ValueError):
            operator.upgrade_semantic_receipts(
                runtime, target, expected_application_sha256="0" * 64
            )

    def test_split_relationship_authority_is_rejected_without_mutation(self):
        from dataclasses import replace

        from daimon_matrix.relationship_store import RelationshipServiceContext

        runtime, spec, sources, _ = application_fixture(self)
        store = self.pair.sender_relationships
        before = store.events()
        runtime = replace(
            runtime,
            service=replace(
                runtime.service,
                relationships=RelationshipServiceContext(
                    store, self.pair.sender_context._card
                ),
            ),
        )
        target = self.root / "split"
        with self.assertRaisesRegex(
            ValueError, "messaging_relationship_composition_rejected"
        ):
            prepare(runtime, target, spec, secret_sources=sources)
        self.assertFalse(target.exists())
        self.assertEqual(store.events(), before)

    def test_published_stores_are_never_recreated(self):
        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        app = load_application(runtime, target)
        channel = app.service.messaging.deliveries["peer-out"].sender.context
        revocation = next(
            e
            for e in self.pair.history
            if e["kind"] == "matrix/relationship-grant-revocation"
        )
        channel.relationships.ingest(revocation)
        for name in spec["stores"].values():
            with self.subTest(store=name):
                path = target / name
                saved = target / (name + ".saved")
                path.rename(saved)
                with self.assertRaisesRegex(
                    ValueError, "messaging_required_store_missing"
                ):
                    load_application(runtime, target)
                self.assertFalse(path.exists())
                saved.rename(path)
        self.assertIn(revocation, channel.relationships.events())

    def test_empty_published_replay_store_fails_closed(self):
        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        for name in spec["stores"].values():
            with self.subTest(store=name):
                path = target / name
                saved = path.read_bytes()
                path.write_bytes(b"")
                try:
                    with self.assertRaisesRegex(
                        ValueError, "messaging_required_store_invalid"
                    ):
                        load_application(runtime, target)
                    self.assertEqual(path.read_bytes(), b"")
                finally:
                    path.write_bytes(saved)

    def test_published_fsync_failure_is_explicit_and_recoverable(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_document

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        sync = operator._sync

        def fail_parent(path):
            if path == target.parent:
                raise OSError("synthetic fsync failure")
            sync(path)

        with (
            patch.object(operator, "_sync", side_effect=fail_parent),
            self.assertRaisesRegex(
                ValueError, "messaging_published_durability_uncertain"
            ),
        ):
            prepare(runtime, target, spec, secret_sources=sources)
        load_application(runtime, target)
        digest = config_digest(read_document(target / "application.json"))
        with self.assertRaisesRegex(ValueError, "messaging_recovery_conflict"):
            operator.recover(runtime, target, expected_application_sha256="0" * 64)
        receipt = operator.recover(runtime, target, expected_application_sha256=digest)
        self.assertEqual(receipt["status"], "configured")
        self.assertEqual(receipt["application_sha256"], digest)

    def test_recover_completes_capability_state_after_renewal_selection_interruption(
        self,
    ):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_publication

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "interrupted-renewal"
        first = prepare(runtime, target, spec, secret_sources=sources)
        self.pair.now += 1
        with (
            patch.object(
                operator,
                "_replace_capability_state",
                side_effect=OSError("synthetic capability-state interruption"),
            ),
            self.assertRaisesRegex(ValueError, "messaging_renewal_rejected"),
        ):
            operator.renew(
                runtime,
                target,
                expected_application_sha256=first["application_sha256"],
            )
        current, _ = read_publication(runtime, target)
        current_digest = config_digest(current)
        self.assertNotEqual(current_digest, first["application_sha256"])
        with self.assertRaisesRegex(ValueError, "messaging_capability_stale"):
            load_application(runtime, target)

        receipt = operator.recover(
            runtime,
            target,
            expected_application_sha256=current_digest,
        )

        self.assertEqual(receipt["status"], "configured")
        loaded = load_application(runtime, target)
        self.assertIn(
            current["client"]["descriptor"]["capability_id"],
            loaded.service.capabilities,
        )

    def test_recover_completes_capability_state_after_pointer_interruption(self):
        from pathlib import Path

        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import (
            _capability_journal_names,
            config_digest,
            read_publication,
        )

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "interrupted-capability-pointer"
        first = prepare(runtime, target, spec, secret_sources=sources)
        initial, _ = read_publication(runtime, target)
        _, stem = _capability_journal_names(runtime, initial["client"]["descriptor"])
        pointer = runtime.state_root / (stem + "-current.json")
        replace = operator.os.replace

        def interrupt_current_pointer(source, destination):
            if Path(destination) == pointer:
                raise OSError("synthetic current-pointer interruption")
            replace(source, destination)

        self.pair.now += 1
        with (
            patch.object(operator.os, "replace", side_effect=interrupt_current_pointer),
            self.assertRaisesRegex(ValueError, "messaging_renewal_rejected"),
        ):
            operator.renew(
                runtime,
                target,
                expected_application_sha256=first["application_sha256"],
            )
        current, _ = read_publication(runtime, target)
        current_digest = config_digest(current)
        with self.assertRaisesRegex(ValueError, "messaging_capability_state_rejected"):
            load_application(runtime, target)

        receipt = operator.recover(
            runtime,
            target,
            expected_application_sha256=current_digest,
        )

        self.assertEqual(receipt["status"], "configured")
        self.assertIsNotNone(load_application(runtime, target).service.messaging)

    def test_operator_renewal_preserves_stores_and_refuses_stale_predecessor(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_document

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        predecessor = config_digest(read_document(target / "application.json"))
        initial = load_application(runtime, target)
        delivery_digest = initial.service.messaging.deliveries["peer-out"].config_digest
        from daimon_matrix.synthetic_relationships import _uuid

        client_id = next(
            c.client_id
            for c in initial.service.capabilities.values()
            if c.client_id.startswith("client:messaging:")
        )
        send_args = dict(
            client_id=client_id,
            send_id=_uuid("renewal-send"),
            thread_id=_uuid("renewal-thread"),
            text="durable pending payload",
        )
        payloads = initial.service.messaging.deliveries["peer-out"].sender.prepare(
            **send_args
        )
        before = {
            name: (target / name).read_bytes() for name in spec["stores"].values()
        }
        self.pair.now += 1
        self.assertIsNotNone(load_application(runtime, target).service.messaging)
        self.assertTrue(
            callable(getattr(operator, "renew", None)), "trusted renewal missing"
        )
        receipt = operator.renew(
            runtime, target, expected_application_sha256=predecessor
        )
        self.assertEqual(receipt["status"], "renewed")
        renewed = load_application(runtime, target)
        self.assertEqual(
            renewed.service.messaging.deliveries["peer-out"].config_digest,
            delivery_digest,
        )
        self.assertNotEqual(receipt["application_sha256"], predecessor)
        self.assertEqual(
            payloads,
            renewed.service.messaging.deliveries["peer-out"].sender.prepare(
                **send_args
            ),
        )
        self.assertEqual(
            before,
            {name: (target / name).read_bytes() for name in spec["stores"].values()},
        )
        with self.assertRaisesRegex(ValueError, "messaging_renewal_conflict"):
            operator.renew(runtime, target, expected_application_sha256=predecessor)
        load_application(runtime, target)

    def test_renewal_publication_failure_boundaries_preserve_state(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_publication

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        receipt = prepare(runtime, target, spec, secret_sources=sources)
        predecessor = receipt["application_sha256"]
        self.pair.now += 1
        pointer = (target / "publication.json").read_bytes()
        stores = {
            name: (target / name).read_bytes() for name in spec["stores"].values()
        }
        with (
            patch.object(operator.os, "replace", side_effect=OSError("synthetic")),
            self.assertRaises(ValueError),
        ):
            operator.renew(runtime, target, expected_application_sha256=predecessor)
        self.assertEqual(pointer, (target / "publication.json").read_bytes())
        load_application(runtime, target)
        sync = operator._sync

        def after_publish(path):
            if path == target and (target / "publication.json").read_bytes() != pointer:
                raise OSError("synthetic post replace")
            sync(path)

        with (
            patch.object(operator, "_sync", side_effect=after_publish),
            self.assertRaisesRegex(
                ValueError, "messaging_published_durability_uncertain"
            ),
        ):
            operator.renew(runtime, target, expected_application_sha256=predecessor)
        self.assertNotEqual(pointer, (target / "publication.json").read_bytes())
        load_application(runtime, target)
        application, metadata = read_publication(runtime, target)
        client = json.loads((metadata / "client.json").read_bytes())
        self.assertEqual(client["capability"], application["client"]["descriptor"])
        operator.recover(
            runtime, target, expected_application_sha256=config_digest(application)
        )
        self.assertEqual(
            stores,
            {name: (target / name).read_bytes() for name in spec["stores"].values()},
        )
        (target / "publication.json").unlink()
        with self.assertRaises(ValueError):
            load_application(runtime, target)
        self.assertFalse((target / "publication.json").exists())

    def test_renewal_cannot_restore_revoked_relationships(self):
        from daimon_matrix.operator_messaging import renew

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        receipt = prepare(runtime, target, spec, secret_sources=sources)
        application = load_application(runtime, target)
        channel = application.service.messaging.deliveries["peer-out"].sender.context
        revocation = next(
            e
            for e in self.pair.history
            if e["kind"] == "matrix/relationship-grant-revocation"
        )
        channel.relationships.ingest(revocation)
        self.pair.now = revocation["occurred_at_ms"] + 1
        pointer = (target / "publication.json").read_bytes()
        with self.assertRaises(ValueError):
            renew(
                runtime,
                target,
                expected_application_sha256=receipt["application_sha256"],
            )
        self.assertEqual(pointer, (target / "publication.json").read_bytes())
        self.assertIn(revocation, channel.relationships.events())
        with self.assertRaises(ValueError):
            load_application(runtime, target)

    def test_renewal_refuses_conflicting_predecessor_client_identity(self):
        from daimon_matrix.operator_messaging import renew

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        receipt = prepare(runtime, target, spec, secret_sources=sources)
        client = json.loads((target / "client.json").read_bytes())
        client["runtime_id"] = "conflicting-runtime"
        (target / "client.json").write_bytes(canonical_bytes(client))
        pointer = (target / "publication.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "messaging_renewal_conflict"):
            renew(
                runtime,
                target,
                expected_application_sha256=receipt["application_sha256"],
            )
        self.assertEqual(pointer, (target / "publication.json").read_bytes())

    def test_postsync_validation_failure_reports_published_state(self):
        from daimon_matrix import operator_messaging as operator

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        real_load = operator.load_application

        def fail_published(runtime, path):
            if path == target:
                raise OSError("synthetic post sync")
            return real_load(runtime, path)

        with (
            patch.object(operator, "load_application", side_effect=fail_published),
            self.assertRaisesRegex(ValueError, "messaging_published_validation_failed"),
        ):
            prepare(runtime, target, spec, secret_sources=sources)
        load_application(runtime, target)
        predecessor = operator.config_digest(
            operator.read_publication(runtime, target)[0]
        )
        self.pair.now += 1
        with (
            patch.object(operator, "load_application", side_effect=fail_published),
            self.assertRaisesRegex(ValueError, "messaging_published_validation_failed"),
        ):
            operator.renew(runtime, target, expected_application_sha256=predecessor)
        load_application(runtime, target)
        self.assertNotEqual(
            predecessor,
            operator.config_digest(operator.read_publication(runtime, target)[0]),
        )

    def test_renewal_requires_a_strictly_later_deadline(self):
        from daimon_matrix.operator_messaging import renew

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        receipt = prepare(runtime, target, spec, secret_sources=sources)
        pointer = (target / "publication.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "messaging_renewal_conflict"):
            renew(
                runtime,
                target,
                expected_application_sha256=receipt["application_sha256"],
            )
        self.assertEqual(pointer, (target / "publication.json").read_bytes())

    def test_closed_schema_grants_binding_and_protected_files(self):
        runtime, spec, sources, _ = application_fixture(self)
        original = copy.deepcopy(spec)
        mutations = [
            lambda c: c.update(extra=True),
            lambda c: c.update(schema="dm.runtime.bundle/v7"),
            lambda c: c["listen"].update(port=True),
            lambda c: c["outgoing"]["policy"].update(max_ttl_ms=60001),
            lambda c: c["outgoing"]["policy"].update(extra=True),
            lambda c: c["incoming"].update(
                recipient_being_ref=c["outgoing"]["recipient_being_ref"]
            ),
            lambda c: c["outgoing"]["policy"]["grant_refs"][0].update(
                grant_id="unknown"
            ),
            lambda c: c["incoming"]["routes"]["evidence"].update(
                endpoint="http://127.0.0.1:45200/wrong"
            ),
            lambda c: c["incoming"]["routes"]["message"].update(
                secret_file="../outside"
            ),
            lambda c: c["stores"].update(inbox="application.json"),
            lambda c: c["stores"].update(inbox=c["stores"]["outbox"] + "-wal"),
            lambda c: c["incoming"]["routes"]["message"].update(secret_sha256="0" * 64),
            lambda c: c["incoming"]["policy"].update(peer_embodiment_id="wrong"),
            lambda c: c["authorities"][0].update(control_head="wrong"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                candidate = copy.deepcopy(original)
                mutate(candidate)
                target = self.root / f"rejected-{index}"
                with self.assertRaises(ValueError):
                    prepare(runtime, target, candidate, secret_sources=sources)
                self.assertFalse(target.exists())
        target = self.root / "valid"
        prepare(runtime, target, spec, secret_sources=sources)
        before = (target / "application.json").read_bytes()
        with self.assertRaises(ValueError):
            prepare(runtime, target, spec, secret_sources=sources)
        self.assertEqual(before, (target / "application.json").read_bytes())
        app = json.loads(before)
        app["outgoing"]["routes"]["message"]["endpoint"] = (
            "http://127.0.0.1:45201/dm-messaging/v1/message"
        )
        (target / "application.json").write_bytes(canonical_bytes(app))
        with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
            load_application(runtime, target)
        (target / "application.json").write_bytes(before)
        for name in (
            "application.json",
            "client.key",
            "incoming-evidence.key",
            "inbox.sqlite",
        ):
            path = target / name
            original_path = target / ("saved-" + name)
            path.rename(original_path)
            path.symlink_to(original_path)
            with self.assertRaises(ValueError):
                load_application(runtime, target)
            path.unlink()
            original_path.rename(path)
        for name in ("client.key", "application.json"):
            path = target / name
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                load_application(runtime, target)
            path.chmod(0o600)
        link = self.root / "app-link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            load_application(runtime, link)
        load_application(runtime, target)

    def test_cli_diagnostics_and_run_use_actual_loader_and_redact(self):
        from daimon_matrix.operator_messaging import main
        from tests.test_dm024_runtime import PASSWORD
        from tests.test_native_messaging import synthetic_visibility_installation

        runtime, spec, _sources, _reads = application_fixture(self)
        visibility_installation = synthetic_visibility_installation(self.root)
        target = self.root / "app"
        spec_path = self.root / "specification.json"
        spec_path.write_bytes(canonical_bytes(spec))
        spec_path.chmod(0o600)

        def call(command, extra=()):
            readfd, writefd = os.pipe()
            os.write(writefd, PASSWORD)
            os.close(writefd)
            output, errors = io.StringIO(), io.StringIO()
            try:
                with (
                    contextlib.redirect_stdout(output),
                    contextlib.redirect_stderr(errors),
                    patch(
                        "time.time_ns", return_value=runtime.service.clock() * 1000000
                    ),
                ):
                    result = main(
                        [
                            command,
                            "--state-root",
                            str(runtime.state_root),
                            "--bundle",
                            "runtime.json",
                            "--app-dir",
                            str(target),
                            "--password-fd",
                            str(readfd),
                        ]
                        + (
                            [
                                "--visibility-installation",
                                str(visibility_installation),
                            ]
                            if command != "prepare"
                            else []
                        )
                        + (
                            ["--visibility-schema-version", "1"]
                            if command == "migrate-visibility"
                            else []
                        )
                        + (
                            ["--spec", str(spec_path), "--secret-dir", str(self.root)]
                            if command == "prepare"
                            else []
                        )
                        + list(extra)
                    )
            finally:
                with contextlib.suppress(OSError):
                    os.close(readfd)
            return result, output.getvalue(), errors.getvalue()

        result, output, errors = call("prepare")
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "configured")
        predecessor = json.loads(output)["application_sha256"]
        visibility_installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )

        visibility_tables = (
            "mandatory_egress_operations",
            "echo_v2_obligations",
            "echo_v2_catalog",
        )
        visibility_stores = (
            target / spec["stores"]["outbox"],
            target / spec["stores"]["opaque-evidence"],
            target / spec["stores"]["opaque-message"],
        )
        for store in visibility_stores:
            with contextlib.closing(sqlite3.connect(store)) as database:
                retained = {
                    row[0]
                    for row in database.execute(
                        "SELECT name FROM sqlite_schema WHERE type='table'"
                    )
                }
            self.assertTrue(set(visibility_tables).isdisjoint(retained))

        def tables(store):
            with contextlib.closing(sqlite3.connect(store)) as database:
                return {
                    row[0]
                    for row in database.execute(
                        "SELECT name FROM sqlite_schema WHERE type='table'"
                    )
                }

        before = {store: tables(store) for store in visibility_stores}
        result, _output, errors = call("diagnostics")
        self.assertEqual(result, 1)
        self.assertEqual(
            {store: tables(store) for store in visibility_stores},
            before,
        )
        result, output, errors = call("migrate-visibility")
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "visibility-migrated")
        self.assertEqual(json.loads(output)["visibility_schema_version"], 1)
        result, _output, _errors = call(
            "migrate-visibility", ["--visibility-schema-version", "2"]
        )
        self.assertEqual(result, 1)
        result, output, errors = call("diagnostics")
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "ready")
        result, _output, _errors = call(
            "migrate-visibility", ["--expected-application-sha256", predecessor]
        )
        self.assertEqual(result, 1)

        self.pair.now += 1
        result, output, errors = call(
            "renew", ["--expected-application-sha256", predecessor]
        )
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "renewed")
        digest = json.loads(output)["application_sha256"]
        visibility_installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        result, output, errors = call(
            "recover", ["--expected-application-sha256", digest]
        )
        self.assertEqual(result, 0, errors)
        result, output, errors = call("diagnostics")
        self.assertEqual(result, 0, errors)
        report = json.loads(output)
        self.assertEqual(report["status"], "ready")
        self.assertFalse(report["mirror_enabled"])
        with patch("daimon_matrix.daemon.serve_forever") as serve:
            result, output, errors = call("run")
            self.assertEqual(result, 0, errors)
            self.assertIsNotNone(serve.call_args.args[0].messaging_http)
        client_key = (target / "client.key").read_bytes()
        (target / "client.key").write_bytes(b"PRIVATE-LEAK-SENTINEL-123456789012")
        result, output, errors = call("diagnostics")
        self.assertEqual(result, 1)
        self.assertNotIn("PRIVATE-LEAK", output + errors)
        self.assertNotIn(PASSWORD.decode(), output + errors)
        self.assertNotIn("Traceback", errors)
        (target / "client.key").write_bytes(client_key)
        result, output, errors = call(
            "revoke", ["--expected-application-sha256", digest]
        )
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "revoked")
        result, output, errors = call(
            "revoke", ["--expected-application-sha256", digest]
        )
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "revoked")
        from daimon_matrix.messaging_config import load_application

        with self.assertRaisesRegex(ValueError, "messaging_capability_revoked"):
            load_application(runtime, target)

    def test_run_entrypoint_real_child_binds_both_transports_and_stops(self):
        import select
        import socket
        import subprocess
        import sys

        from tests.test_dm024_runtime import PASSWORD
        from tests.test_native_messaging import synthetic_visibility_installation

        runtime, spec, sources, _ = application_fixture(self)
        visibility_installation = synthetic_visibility_installation(self.root)
        with socket.socket() as peer_socket, socket.socket() as app_socket:
            peer_socket.bind(("127.0.0.1", 0))
            app_socket.bind(("127.0.0.1", 0))
            peer_port = peer_socket.getsockname()[1]
            app_port = app_socket.getsockname()[1]
        bundle_path = runtime.state_root / "runtime.json"
        bundle = json.loads(bundle_path.read_bytes())
        bundle["peer_transport"]["listen_port"] = peer_port
        bundle_path.write_bytes(canonical_bytes(bundle))
        spec["listen"]["port"] = app_port
        for phase in ("evidence", "message"):
            spec["incoming"]["routes"][phase]["endpoint"] = (
                f"http://127.0.0.1:{app_port}/dm-messaging/v1/{phase}"
            )
        target = self.root / "child-app"
        prepare(runtime, target, spec, secret_sources=sources)
        visibility_installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        readfd, writefd = os.pipe()
        readyread, readywrite = os.pipe()
        os.write(writefd, PASSWORD)
        os.close(writefd)
        # Synthetic clock stays in this test wrapper, never a production CLI option.
        script = (
            f"import time; time.time_ns=lambda: {runtime.service.clock() * 1000000}; "
            "from daimon_matrix.operator_messaging import main; "
            "raise SystemExit(main())"
        )
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                "run",
                "--state-root",
                str(runtime.state_root),
                "--bundle",
                "runtime.json",
                "--app-dir",
                str(target),
                "--password-fd",
                str(readfd),
                "--visibility-installation",
                str(visibility_installation),
                "--ready-fd",
                str(readywrite),
            ],
            pass_fds=(readfd, readywrite),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(readfd)
        os.close(readywrite)
        try:
            self.assertTrue(
                select.select([readyread], [], [], 20)[0], "child readiness timeout"
            )
            ready = os.read(readyread, 4096)
            if not ready:
                child_output, child_errors = child.communicate(timeout=5)
                self.fail(
                    "child exited without readiness: "
                    + repr((child.returncode, child_output, child_errors))
                )
            self.assertIsNone(child.poll())
            for port in (peer_port, app_port):
                with socket.create_connection(("127.0.0.1", port), timeout=3):
                    pass
            self.assertTrue(runtime.socket_path.exists())
        finally:
            os.close(readyread)
            child.terminate()
            try:
                stdout, stderr = child.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr.decode())
        self.assertNotIn(PASSWORD, stdout + stderr)
        self.assertFalse(runtime.socket_path.exists())
