"""Provisioning negative controls and operator entrypoint; no live enrollment."""

import contextlib
import copy
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
import uuid
from dataclasses import replace
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


class ExclusivePublicationTests(unittest.TestCase):
    def test_real_exclusive_publication_and_existing_empty_destination(self):
        from daimon_matrix.operator_messaging import _publish

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            staging, target = root / "staging", root / "target"
            staging.mkdir()
            (staging / "sentinel").write_bytes(b"preserve")
            _publish(staging, target)
            self.assertFalse(staging.exists())
            self.assertEqual((target / "sentinel").read_bytes(), b"preserve")
            another = root / "another"
            another.mkdir()
            empty = root / "existing-empty"
            empty.mkdir()
            inode = empty.stat().st_ino
            with self.assertRaisesRegex(ValueError, "destination_exists"):
                _publish(another, empty)
            self.assertTrue(another.is_dir())
            self.assertEqual(empty.stat().st_ino, inode)
            link = root / "link"
            link.symlink_to(empty, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "destination_exists"):
                _publish(another, link)
            self.assertTrue(link.is_symlink())

    def test_unsupported_platform_and_missing_symbol_have_no_rename_fallback(self):
        from types import SimpleNamespace

        from daimon_matrix import operator_messaging as operator

        with (
            patch.object(operator.sys, "platform", "unsupported"),
            patch.object(operator.ctypes, "CDLL") as load,
            self.assertRaisesRegex(ValueError, "publication_unsupported"),
        ):
            operator._publish(Path("source"), Path("target"))
        load.assert_not_called()
        for platform in ("linux", "darwin"):
            with (
                patch.object(operator.sys, "platform", platform),
                patch.object(operator.ctypes, "CDLL", return_value=SimpleNamespace()),
                self.assertRaisesRegex(ValueError, "publication_unsupported"),
            ):
                operator._publish(Path("source"), Path("target"))


class ProvisioningTests(unittest.TestCase):
    def test_peer_presentation_cli_keeps_primary_catalogs_with_distinct_proof_key(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import verify_binding
        from daimon_matrix.telegram_mirror import PlainTelegramTransport
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        app = self.root / "presentation-app"
        prepare(runtime, app, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, app
        )
        # The base native catalogs retain their primary controller's key.
        # A peer application has its own independently accepted proof key.
        proof_key = b"\x88" * 32
        (self.root / "echo-proof.key").write_bytes(proof_key)
        envelope = json.loads(installation.read_bytes())
        envelope["document"]["policy"]["proof_key_id"] = (
            "sha256:" + hashlib.sha256(proof_key).hexdigest()
        )
        envelope["binding"] = create_binding(runtime, envelope["document"])
        installation.write_bytes(canonical_bytes(envelope))
        retained = {
            path: path.read_bytes()
            for path in (
                runtime.state_root / "peer-exchange.sqlite",
                runtime.state_root / "peer-outbox.sqlite",
                runtime.state_root / "custody.json",
                installation,
            )
        }

        def invoke(output, *, command="visibility-propose", proposal=None):
            reader, writer = os.pipe()
            os.write(writer, PASSWORD)
            os.close(writer)
            stdout, stderr = io.StringIO(), io.StringIO()
            try:
                with (
                    patch("time.time_ns", return_value=self.pair.now * 1_000_000),
                    patch.object(
                        PlainTelegramTransport,
                        "send",
                        side_effect=AssertionError("offline presentation sent traffic"),
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    arguments = [
                        command,
                        "--state-root",
                        str(runtime.state_root),
                        "--app-dir",
                        str(app),
                        "--password-fd",
                        str(reader),
                        "--visibility-installation",
                        str(installation),
                    ]
                    if command == "visibility-propose":
                        arguments += ["--representation", "compact-text/v1"]
                    if output is not None:
                        arguments += ["--output", str(output)]
                    if proposal is not None:
                        arguments += ["--proposal", str(proposal)]
                    result = operator.main(arguments)
                return result, stdout.getvalue(), stderr.getvalue()
            finally:
                # The CLI password reader owns and closes a consumed descriptor.
                with contextlib.suppress(OSError):
                    os.close(reader)

        output = self.root / "presentation-proposal.json"
        result, stdout, stderr = invoke(output)
        self.assertEqual(result, 0, stderr)
        self.assertEqual(json.loads(stdout)["status"], "presentation-proposal-signed")
        proposal = json.loads(output.read_bytes())
        self.assertEqual(
            proposal["disclosure"]["destination"]["representation"], "compact-text/v1"
        )
        verify_binding(runtime, proposal["disclosure"], proposal["bindings"][0])
        accepted = self.root / "accepted-proposal.json"
        result, _, stderr = invoke(
            accepted, command="visibility-accept", proposal=output
        )
        self.assertEqual(result, 0, stderr)
        result, _, stderr = invoke(None, command="visibility-apply", proposal=accepted)
        self.assertEqual(result, 1)
        self.assertIn("acceptance_missing", stderr)
        self.assertEqual({p: p.read_bytes() for p in retained}, retained)

        # Signing-only bootstrap must still authenticate the selected installation.
        envelope["document"]["generation"] += 1
        installation.write_bytes(canonical_bytes(envelope))
        refused_output = self.root / "refused-proposal.json"
        result, _, stderr = invoke(refused_output)
        self.assertEqual(result, 1)
        self.assertTrue(stderr)
        self.assertFalse(refused_output.exists())

    def test_native_owner_presentation_binds_bundle_without_an_application(self):
        from daimon_matrix.daemon import acquire_lock
        from daimon_matrix.operator_messaging import visibility_presentation
        from tests.test_dm024_runtime import signed_runtime_visibility_installation
        from tests.test_messaging_runtime import loaded

        fixture, runtime, _ = loaded(self)
        bundle_path = runtime.state_root / "runtime.json"
        bundle = json.loads(bundle_path.read_bytes())
        installation = signed_runtime_visibility_installation(
            fixture, runtime.state_root, bundle, runtime.service.clock()
        )
        before = installation.read_bytes()
        custody = (runtime.state_root / "custody.json").read_bytes()
        descriptor = acquire_lock(runtime.state_root)
        try:
            proposal = visibility_presentation(
                runtime,
                None,
                installation,
                command="visibility-propose",
                representation="compact-text/v1",
            )
            result = visibility_presentation(
                runtime,
                None,
                installation,
                command="visibility-apply",
                proposal=proposal,
            )
            self.assertEqual(result["status"], "presentation-selected")
            self.assertEqual(
                (
                    installation.parent / result["previous_installation_backup"]
                ).read_bytes(),
                before,
            )
            selected = json.loads(installation.read_bytes())["document"]
            self.assertEqual(selected["application_sha256"], config_digest(bundle))
            self.assertEqual(selected["policy"]["representation"], "compact-text/v1")
            self.assertEqual(
                (runtime.state_root / "custody.json").read_bytes(), custody
            )
            self.assertEqual(
                visibility_presentation(
                    runtime,
                    None,
                    installation,
                    command="visibility-apply",
                    proposal=proposal,
                )["status"],
                "unchanged",
            )
            # A different selected bundle cannot borrow this installation.
            other = {**bundle, "runtime_label": "different"}
            other_path = runtime.state_root / "other.json"
            other_path.write_bytes(canonical_bytes(other))
            other_path.chmod(0o600)
            with self.assertRaises(ValueError):
                visibility_presentation(
                    runtime,
                    None,
                    installation,
                    command="visibility-propose",
                    representation="compact-text/v1",
                    bundle_name="other.json",
                )
            with self.assertRaises(ValueError):
                visibility_presentation(
                    runtime,
                    None,
                    installation,
                    command="visibility-propose",
                    representation="compact-text/v1",
                    bundle_name="../other.json",
                )
        finally:
            os.close(descriptor)

    def test_same_audience_presentation_successor_preserves_keys_stores_and_rollback(
        self,
    ):
        from daimon_matrix.operator_messaging import visibility_presentation

        runtime, spec, sources, _ = application_fixture(self)
        app = self.root / "presentation-app"
        prepare(runtime, app, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, app
        )
        previous = installation.read_bytes()
        retained = {p: p.read_bytes() for p in app.iterdir() if p.is_file()}
        secrets = {
            p: p.read_bytes()
            for p in (self.root / "telegram.token", self.root / "echo-proof.key")
        }
        proposal = visibility_presentation(
            runtime,
            app,
            installation,
            command="visibility-propose",
            representation="compact-text/v1",
        )
        self.assertEqual(installation.read_bytes(), previous)
        with self.assertRaisesRegex(ValueError, "acceptance_missing"):
            visibility_presentation(
                runtime,
                app,
                installation,
                command="visibility-apply",
                proposal=proposal,
            )
        widened = copy.deepcopy(proposal)
        widened["disclosure"]["destination"]["chat_id"] -= 1
        with self.assertRaisesRegex(ValueError, "scope_change"):
            visibility_presentation(
                runtime,
                app,
                installation,
                command="visibility-accept",
                proposal=widened,
            )
        # The independently held receiving identity signs the exact same proposal.
        peer = self.pair.recipient
        old_peer_binding = next(
            b
            for b in json.loads(previous)["document"]["acceptance_set"]["bindings"]
            if b["body"]["being_ref"] == peer.state.being_ref
        )
        body = {
            **old_peer_binding["body"],
            "application_sha256": config_digest(proposal["disclosure"]),
        }
        proposal["bindings"].append(
            {
                "schema": old_peer_binding["schema"],
                "body": body,
                "signature": b64url(
                    Ed25519PrivateKey.from_private_bytes(peer.signer.seed).sign(
                        BINDING_DOMAIN + canonical_bytes(body)
                    )
                ),
            }
        )
        tampered = copy.deepcopy(proposal)
        tampered["bindings"][-1]["signature"] = "A" * 86
        with self.assertRaises(ValueError):
            visibility_presentation(
                runtime,
                app,
                installation,
                command="visibility-apply",
                proposal=tampered,
            )
        self.assertEqual(installation.read_bytes(), previous)
        foreign_old = copy.deepcopy(json.loads(previous)["document"]["disclosure"])
        for channel in foreign_old["scope"]["channels"]:
            channel["local_being_ref"], channel["peer_being_ref"] = (
                channel["peer_being_ref"],
                channel["local_being_ref"],
            )
        foreign_old["scope_sha256"] = config_digest(foreign_old["scope"])

        def peer_signature(document):
            signed_body = {
                **old_peer_binding["body"],
                "application_sha256": config_digest(document),
            }
            return {
                "schema": old_peer_binding["schema"],
                "body": signed_body,
                "signature": b64url(
                    Ed25519PrivateKey.from_private_bytes(peer.signer.seed).sign(
                        BINDING_DOMAIN + canonical_bytes(signed_body)
                    )
                ),
            }

        old_bindings = {
            runtime.service.ledger.authority.manifest.being_ref: create_binding(
                runtime, foreign_old
            ),
            peer.state.being_ref: peer_signature(foreign_old),
        }
        foreign_new = copy.deepcopy(foreign_old)
        foreign_new["destination"]["representation"] = "compact-text/v1"
        foreign = {
            "schema": proposal["schema"],
            "disclosure": foreign_new,
            "bindings": [peer_signature(foreign_new)],
            "predecessor": {
                "disclosure": foreign_old,
                "acceptance_set": {
                    "schema": "dm.messaging.visibility-acceptance-set/v1",
                    "disclosure_sha256": config_digest(foreign_old),
                    "bindings": [
                        old_bindings[actor] for actor in foreign_old["participants"]
                    ],
                },
            },
        }
        # A different directional declaration is accepted only with its actual
        # previous signatures, and cannot replace this endpoint's own policy.
        accepted_foreign = visibility_presentation(
            runtime, app, installation, command="visibility-accept", proposal=foreign
        )
        self.assertEqual(len(accepted_foreign["bindings"]), 2)
        with self.assertRaisesRegex(ValueError, "presentation_conflict"):
            visibility_presentation(
                runtime,
                app,
                installation,
                command="visibility-apply",
                proposal=accepted_foreign,
            )
        self.assertEqual(installation.read_bytes(), previous)
        forged_previous = copy.deepcopy(foreign)
        forged_previous["predecessor"]["acceptance_set"]["bindings"][0]["signature"] = (
            "A" * 86
        )
        with self.assertRaises(ValueError):
            visibility_presentation(
                runtime,
                app,
                installation,
                command="visibility-accept",
                proposal=forged_previous,
            )
        result = visibility_presentation(
            runtime, app, installation, command="visibility-apply", proposal=proposal
        )
        self.assertEqual(result["status"], "presentation-selected")
        self.assertEqual(result["generation"], 2)
        self.assertEqual(
            (self.root / result["previous_installation_backup"]).read_bytes(), previous
        )
        self.assertEqual(retained, {p: p.read_bytes() for p in retained})
        self.assertEqual(secrets, {p: p.read_bytes() for p in secrets})
        selected = json.loads(installation.read_bytes())["document"]
        self.assertEqual(selected["policy"]["representation"], "compact-text/v1")
        self.assertEqual(
            selected["telegram_qualification"],
            json.loads(previous)["document"]["telegram_qualification"],
        )
        after = installation.read_bytes()
        repeated = visibility_presentation(
            runtime, app, installation, command="visibility-apply", proposal=proposal
        )
        self.assertEqual(repeated["status"], "unchanged")
        self.assertEqual(installation.read_bytes(), after)

    def test_host_visibility_accepts_current_authority_with_history_wrapper(self):
        from daimon_matrix.authority_epochs import RootHistoryAuthority
        from daimon_matrix.operator_messaging import host_visibility_factory
        from daimon_matrix.runtime import load_runtime
        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "history-host-app"
        prepare(runtime, target, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        factory = host_visibility_factory(
            target, installation, clock=lambda: self.pair.now
        )

        def with_history(context):
            # Exercise the public factory with a verified history wrapper. A
            # wrapper is not itself equal to its otherwise identical active head.
            history = RootHistoryAuthority(context.authority, [], [])
            controller = factory(replace(context, authority=history))
            # A different current authority must still fail closed.
            with self.assertRaises(ValueError):
                factory(
                    replace(
                        context,
                        authority=RootHistoryAuthority(
                            self.pair.recipient.authority, [], []
                        ),
                    )
                )
            return controller

        restarted = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: self.pair.now,
            egress_factory=with_history,
        )
        self.assertTrue(restarted.egress.release_enabled)
        self.assertIs(load_application(restarted, target).egress, restarted.egress)

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

    def test_initial_prepare_preserves_private_stage_after_capability_effect(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import read_capability_state

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "interrupted-initial-application"
        with (
            patch.object(operator, "_compose", side_effect=OSError("interrupted")),
            self.assertRaisesRegex(ValueError, "messaging_prepare_rejected"),
        ):
            operator.prepare(runtime, target, spec, secret_sources=sources)

        self.assertFalse(target.exists())
        stages = list(target.parent.glob(".messaging-prepare-*"))
        self.assertEqual(
            len(stages), 1, "durable genesis must retain its original client"
        )
        application = json.loads((stages[0] / "application.json").read_bytes())
        client = application["client"]
        self.assertEqual(
            hashlib.sha256((stages[0] / "client.key").read_bytes()).hexdigest(),
            client["secret_sha256"],
        )
        self.assertEqual(
            read_capability_state(runtime, client["descriptor"])["capability_id"],
            client["descriptor"]["capability_id"],
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
                try:
                    with self.assertRaisesRegex(
                        ValueError, "messaging_required_store_missing"
                    ):
                        load_application(runtime, target)
                    self.assertFalse(path.exists())
                finally:
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
            if path == target.parent and target.exists():
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


class RetainedVisibilityAcceptanceTests(unittest.TestCase):
    def test_signed_retirement_preserves_only_current_body_acceptance(self):
        from daimon_matrix.authority_epochs import (
            RootHistoryAuthority,
            create_embodiment_retirement,
        )
        from daimon_matrix.identity import create_revocation, verify_successor
        from daimon_matrix.messaging_config import (
            MessagingConfigError,
            verify_visibility_participant,
        )
        from daimon_matrix.weave import BeingManifest, RootAuthority
        from tests.test_dm022_ledger import NOW, RootLedgerFixture

        fixture = RootLedgerFixture()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        previous = fixture.authority
        document = {"issued_at_ms": NOW - 50, "scope": "unchanged"}
        # Disclosure predates incarnation start: binding has no signing time.
        bindings = {}
        for label in ("legion", "daimonmatrix"):
            identity = _public_identity(
                previous, fixture.origins[label], "runtime", "runtime", NOW
            )
            body = {**identity, "application_sha256": config_digest(document)}
            bindings[label] = {
                "schema": "dm.messaging.operator-binding/v1",
                "body": body,
                "signature": b64url(
                    Ed25519PrivateKey.from_private_bytes(
                        fixture.signing_seeds[label]
                    ).sign(BINDING_DOMAIN + canonical_bytes(body))
                ),
            }
            verify_visibility_participant(
                previous,
                previous.manifest.being_ref,
                document,
                bindings[label],
                at_ms=NOW,
            )
        control = create_revocation(
            previous.state,
            fixture.root_seeds,
            embodiment_id="embodiment:daimonmatrix",
            revocation_generation=1,
            cutoff_incarnation_sequence=0,
        )
        state = verify_successor(control, previous.state)
        value = copy.deepcopy(dict(previous.manifest.value))
        value.update(control_head=state.head, revision=value["revision"] + 1)
        for member in value["embodiments"]:
            if member["embodiment_id"] == "embodiment:daimonmatrix":
                member["status"] = "retired"
        active = RootAuthority(
            BeingManifest.from_value(value),
            state,
            previous.credentials,
            previous.incarnations,
        )
        transition = create_embodiment_retirement(
            previous.manifest,
            active.manifest,
            revocations=[control],
            root_seeds=fixture.root_seeds,
            issued_at_ms=NOW + 10,
        )
        history = RootHistoryAuthority(active, [previous], [transition])
        verify_visibility_participant(
            history,
            previous.manifest.being_ref,
            document,
            bindings["legion"],
            at_ms=NOW + 20,
        )
        with self.assertRaises(MessagingConfigError):
            verify_visibility_participant(
                history,
                previous.manifest.being_ref,
                document,
                bindings["daimonmatrix"],
                at_ms=NOW + 20,
            )
        for changed in (
            {**document, "scope": "changed"},
            {**document, "issued_at_ms": NOW + 21},
        ):
            with self.assertRaises(MessagingConfigError):
                verify_visibility_participant(
                    history,
                    previous.manifest.being_ref,
                    changed,
                    bindings["legion"],
                    at_ms=NOW + 20,
                )

    def test_republish_recovers_selected_publication_before_installation_reissue(self):
        from daimon_matrix.operator_messaging import republish
        from tests.test_republish_after_advance import (
            advance_manifest,
            daemon_visibility_check,
        )

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        advanced = advance_manifest(runtime)
        with (
            patch(
                "daimon_matrix.operator_messaging._reissue_installation",
                side_effect=OSError("interrupted"),
            ),
            self.assertRaises(ValueError),
        ):
            republish(advanced, target, installation=installation)
        selected = read_publication(advanced, target)[1]
        before = sorted(path.name for path in target.iterdir())
        receipt = republish(advanced, target, installation=installation)
        self.assertEqual(receipt["status"], "current")
        self.assertTrue(receipt["installation"]["reissued"])
        self.assertEqual(read_publication(advanced, target)[1], selected)
        self.assertEqual(sorted(path.name for path in target.iterdir()), before)
        daemon_visibility_check(advanced, target, installation)


class GroupApplicationAdmissionTests(unittest.TestCase):
    def setUp(self):
        from daimon_matrix.native_egress import closed_visibility
        from tests.test_dm051_sealed import TribeConversationLaneTests
        from tests.test_group_messaging_runtime import GroupRuntimeTests
        from tests.test_messaging_runtime import public_document

        self.fixture = TribeConversationLaneTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.runtime, self.app, self.view = GroupRuntimeTests._signed_group_application(
            self, record_key_check=False, founder_only=True
        )
        # The admission owner starts after the predecessor writer is quiesced.
        # Its closed controller has no already-bound predecessor reader context.
        self.runtime = replace(
            self.runtime,
            egress=closed_visibility(
                clock=lambda: self.fixture.now, catalog_mode="migrate"
            ),
        )
        self.previous, _ = read_publication(self.runtime, self.app)
        self.expected = config_digest(self.previous)
        self.candidate = copy.deepcopy(self.previous)
        member = self.fixture.member
        self.admitted = [member.state.being_ref]
        self.candidate["authorities"].append(public_document(member, "member"))
        self.candidate["relationship_events"] = [
            *self.previous["relationship_events"],
            *[
                event
                for event in self.fixture.events
                if event not in self.previous["relationship_events"]
            ],
        ]
        key = self.app.parent / "admitted-body.key"
        key.write_bytes(b"n" * 32)
        key.chmod(0o600)
        self.sources = {key.name: key}
        route = {
            "provider_ref": "admitted-body",
            "route_ref": "admitted-body",
            "key_ref": "admitted-body",
            "endpoint": "http://127.0.0.1:48766/dm-messaging/v1/message",
            "secret_file": key.name,
            "secret_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
        }
        self.candidate["roster"].append(
            {
                "being_ref": member.state.being_ref,
                "embodiment_id": member.origin["embodiment_id"],
                "body_ref": member.origin["body_ref"],
                "route": route,
            }
        )

    def accept(self):
        for event in self.fixture.events:
            self.runtime.service.relationships.store.ingest(event)

    def publish(self, **changes):
        from daimon_matrix.operator_messaging import admit_group_application

        options = {
            "expected_application_sha256": self.expected,
            "admitted_being_refs": self.admitted,
            "secret_sources": self.sources,
        }
        options.update(changes)
        return admit_group_application(
            self.runtime, self.app, self.candidate, **options
        )

    def test_publication_preserves_client_keys_stores_and_exact_retry(self):
        self.accept()
        client = (self.app / "client.key").read_bytes()
        old_key = self.app / self.previous["intake"]["secret_file"]
        key_bytes = old_key.read_bytes()
        stores = {
            filename: (self.app / filename).stat().st_ino
            for filename in self.previous["stores"].values()
        }
        record = {"summary": "retained before admission"}
        record_id = str(uuid.uuid4())
        self.view.service.messaging.channels["tribe"].records.reserve(
            "request", record_id, record, lambda: record
        )
        first = self.publish()
        self.assertEqual(first["status"], "group-application-published")
        selected, metadata = read_publication(self.runtime, self.app)
        self.assertEqual(selected, self.candidate)
        self.assertEqual(selected["client"], self.previous["client"])
        self.assertEqual((self.app / "client.key").read_bytes(), client)
        self.assertEqual(old_key.read_bytes(), key_bytes)
        self.assertEqual(
            {name: (self.app / name).stat().st_ino for name in stores}, stores
        )
        group = load_application(self.runtime, self.app).service.messaging.channels[
            "tribe"
        ]
        self.assertEqual(group.records.get("request", record_id), record)
        self.assertEqual(len(group.receiving_roster()["audience"]), 2)
        files = sorted(self.app.iterdir())
        publication = (self.app / "publication.json").read_bytes()
        again = self.publish()
        self.assertEqual(again, {**first, "status": "current"})
        self.assertEqual(sorted(self.app.iterdir()), files)
        self.assertEqual((self.app / "publication.json").read_bytes(), publication)
        self.assertEqual(metadata.name, first["generation"])

    def test_lost_reply_recovers_without_reminting_client_or_generation(self):
        self.accept()
        replace_file = os.replace

        def lost_reply(source, destination):
            result = replace_file(source, destination)
            if Path(destination) == self.app / "publication.json":
                raise OSError("lost reply after publication")
            return result

        with (
            patch(
                "daimon_matrix.operator_messaging.os.replace", side_effect=lost_reply
            ),
            self.assertRaises(OSError),
        ):
            self.publish()
        before, metadata = read_publication(self.runtime, self.app)
        client = (self.app / "client.key").read_bytes()
        result = self.publish()
        self.assertEqual(result["status"], "current")
        self.assertEqual(read_publication(self.runtime, self.app), (before, metadata))
        self.assertEqual((self.app / "client.key").read_bytes(), client)

    def test_torn_staging_key_recovers_before_selecting_the_same_generation(self):
        self.accept()
        from daimon_matrix.operator_messaging import _write

        def interrupted(directory, name, raw):
            if directory.name == "transport-staging" and ".stage-" in name:
                _write(directory, name, raw[:8])
                raise OSError("interrupted staging write")
            return _write(directory, name, raw)

        with (
            patch("daimon_matrix.operator_messaging._write", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            self.publish()
        self.assertEqual(read_publication(self.runtime, self.app)[0], self.previous)
        result = self.publish()
        self.assertEqual(result["status"], "group-application-published")
        self.assertEqual(list(self.app.rglob("*.stage-*")), [])
        self.assertEqual((self.app / "admitted-body.key").read_bytes(), b"n" * 32)

    def test_new_key_staging_never_deletes_an_old_key_with_a_stage_shaped_name(self):
        from daimon_matrix.native_egress import closed_visibility

        collision = "route.key.stage-" + "a" * 32
        original_key = self.app / self.previous["intake"]["secret_file"]
        specification = copy.deepcopy(self.previous)
        del specification["client"]
        for route in (
            specification["intake"],
            *[row["route"] for row in specification["roster"]],
        ):
            route["secret_file"] = collision
        other_app = self.app.parent / "collision-application"
        prepare(
            self.runtime,
            other_app,
            specification,
            secret_sources={collision: original_key},
        )
        self.runtime = replace(
            self.runtime,
            egress=closed_visibility(
                clock=lambda: self.fixture.now, catalog_mode="migrate"
            ),
        )
        self.app = other_app
        self.previous, _ = read_publication(self.runtime, self.app)
        self.expected = config_digest(self.previous)
        self.candidate["client"] = self.previous["client"]
        self.candidate["intake"] = self.previous["intake"]
        self.candidate["roster"][0] = self.previous["roster"][0]
        self.candidate["roster"][1]["route"]["secret_file"] = "route.key"
        self.sources = {"route.key": next(iter(self.sources.values()))}
        before = (self.app / collision).read_bytes()
        self.accept()
        self.publish()
        self.assertEqual((self.app / collision).read_bytes(), before)
        self.assertEqual((self.app / "route.key").read_bytes(), b"n" * 32)

    def test_lost_key_rename_reply_resyncs_both_directories_on_exact_retry(self):
        from daimon_matrix.operator_messaging import _publish, _sync

        self.accept()

        def interrupted(source, destination):
            _publish(source, destination)
            if Path(destination) == self.app / "admitted-body.key":
                raise OSError("lost key rename reply")

        with (
            patch("daimon_matrix.operator_messaging._publish", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            self.publish()
        self.assertEqual(read_publication(self.runtime, self.app)[0], self.previous)
        self.assertEqual((self.app / "admitted-body.key").read_bytes(), b"n" * 32)
        synced = []

        def sync(directory):
            _sync(directory)
            synced.append(directory)

        with patch("daimon_matrix.operator_messaging._sync", side_effect=sync):
            result = self.publish()
        generation = self.app / result["generation"]
        self.assertIn(generation / "transport-staging", synced)
        self.assertIn(generation, synced)
        self.assertIn(self.app, synced)

    def test_unaccepted_member_is_rejected_before_candidate_files_are_written(self):
        files = sorted(self.app.iterdir())
        with self.assertRaisesRegex(ValueError, "messaging_group_admission_conflict"):
            self.publish()
        self.assertEqual(read_publication(self.runtime, self.app)[0], self.previous)
        self.assertEqual(sorted(self.app.iterdir()), files)

    def member_application(self):
        from daimon_matrix.messaging_config import application_routes
        from daimon_matrix.relationship_store import (
            RelationshipServiceContext,
            RelationshipStore,
        )
        from daimon_matrix.synthetic_relationships import _seed
        from tests.test_messaging_runtime import loaded, public_document

        # The legacy factory hard-codes founder seed labels. Supply this genuine
        # synthetic member's public genesis and encryption input instead; native
        # runtime, custody and application verification remain unmodified.
        def identity_document(identity, _label):
            return public_document(identity, "member")

        def identity_seed(label):
            return _seed(
                "member:encryption" if label == "founder:encryption" else label
            )

        with (
            patch("tests.test_messaging_runtime.public_document", identity_document),
            patch("daimon_matrix.synthetic_relationships._seed", identity_seed),
        ):
            _, runtime, _ = loaded(
                self, self.fixture.member, clock=lambda: self.fixture.now
            )
        ordinary = RelationshipStore(
            runtime.state_root / "relationships.sqlite",
            authority_resolver=self.fixture.receiver_lane.authority_resolver,
        )
        for event in self.fixture.events:
            ordinary.ingest(event)
        runtime.service.communication.upgrade_receipts_v2()
        runtime.service.communication.upgrade_legs_v3()
        runtime = replace(
            runtime,
            service=replace(
                runtime.service,
                relationships=RelationshipServiceContext(
                    ordinary,
                    self.fixture.journey.card_verifier,
                    self.fixture.receiver_lane.authority_resolver,
                ),
            ),
        )
        specification = copy.deepcopy(self.candidate)
        del specification["client"]
        specification["listen"]["port"] = 48766
        specification["intake"] = specification["roster"][1]["route"]
        specification["tribe"]["policy"]["membership_ref"] = self.fixture.membership_ref
        specification["relationship_mode"].update(
            runtime_id=runtime.service.runtime_id,
            state_root=str(runtime.state_root),
            store_filename=ordinary.path.name,
        )
        sources = {
            row["secret_file"]: self.app / row["secret_file"]
            for row in application_routes(specification)
        }
        app = runtime.state_root.parent / "member-group-application"
        prepare(runtime, app, specification, secret_sources=sources)
        return runtime, app

    def test_each_real_owner_signs_the_exact_group_disclosure_as_itself(self):
        from daimon_matrix.messaging_config import verify_visibility_participant
        from daimon_matrix.operator_messaging import (
            accept_group_visibility,
            group_visibility_disclosure,
        )

        self.accept()
        self.publish()
        destination = {
            "bot_id": 137,
            "chat_id": -100137,
            "topic_id": None,
            "representation": "compact-html/v1",
        }
        disclosure = group_visibility_disclosure(
            self.runtime,
            self.app,
            approved_destination=destination,
            issued_at_ms=self.fixture.now,
        )
        other, other_app = self.member_application()
        for runtime, app, authority in (
            (self.runtime, self.app, self.fixture.founder.authority),
            (other, other_app, self.fixture.member.authority),
        ):
            binding = accept_group_visibility(
                runtime, app, disclosure, approved_destination=destination
            )
            self.assertEqual(binding["body"]["being_ref"], authority.manifest.being_ref)
            verify_visibility_participant(
                authority,
                authority.manifest.being_ref,
                disclosure,
                binding,
                at_ms=self.fixture.now,
            )
            self.assertEqual(
                accept_group_visibility(
                    runtime, app, disclosure, approved_destination=destination
                ),
                binding,
            )

    def test_visibility_signature_refuses_peer_selected_destination_or_scope(self):
        from daimon_matrix.operator_messaging import (
            accept_group_visibility,
            group_visibility_disclosure,
        )

        self.accept()
        self.publish()
        destination = {
            "bot_id": 137,
            "chat_id": -100137,
            "topic_id": None,
            "representation": "compact-html/v1",
        }
        original = group_visibility_disclosure(
            self.runtime,
            self.app,
            approved_destination=destination,
            issued_at_ms=self.fixture.now,
        )
        altered = []
        for name, value in (
            ("participants", original["participants"][:1]),
            ("risk", "different-risk"),
            ("issued_at_ms", self.fixture.now + 1),
            ("extra", "unapproved"),
        ):
            altered.append({**original, name: value})
        wrong_chat = copy.deepcopy(original)
        wrong_chat["destination"]["chat_id"] -= 1
        altered.append(wrong_chat)
        wrong_member = copy.deepcopy(original)
        wrong_member["scope"]["channels"][0]["membership_ref"] = "other-membership"
        wrong_member["scope_sha256"] = config_digest(wrong_member["scope"])
        altered.append(wrong_member)
        with patch(
            "daimon_matrix.operator_messaging.create_binding",
            side_effect=AssertionError("invalid disclosure reached signing"),
        ):
            for disclosure in altered:
                with self.subTest(disclosure=disclosure), self.assertRaises(ValueError):
                    accept_group_visibility(
                        self.runtime,
                        self.app,
                        disclosure,
                        approved_destination=destination,
                    )

    def visibility_configuration(self):
        directory = self.app.parent / "group-visibility"
        directory.mkdir(mode=0o700)
        token = b"137:SIGNED_TEST_ONLY"
        proof = b"v" * 32
        for name, raw in (("telegram.token", token), ("proof.key", proof)):
            path = directory / name
            path.write_bytes(raw)
            path.chmod(0o600)
        return directory / "installation.json", {
            "destination": {
                "bot_id": 137,
                "chat_id": -100137,
                "topic_id": None,
                "representation": "compact-html/v1",
            },
            "secrets": {
                "telegram_token_file": "telegram.token",
                "telegram_token_sha256": hashlib.sha256(token).hexdigest(),
                "proof_key_file": "proof.key",
            },
            "telegram_qualification": {
                "schema": "dm.messaging.telegram-qualification/v1",
                "qualified_at_ms": self.fixture.now,
                "token_sha256": hashlib.sha256(token).hexdigest(),
                "get_me_bot_id": 137,
                "probe_chat_id": -100137,
                "probe_topic_id": None,
                "probe_message_id": 1,
                "probe_text_sha256": "b" * 64,
            },
        }

    def accepted_disclosure(self, destination):
        from daimon_matrix.operator_messaging import (
            accept_group_visibility,
            group_visibility_disclosure,
        )

        disclosure = group_visibility_disclosure(
            self.runtime,
            self.app,
            approved_destination=destination,
            issued_at_ms=self.fixture.now,
        )
        bindings = [
            accept_group_visibility(
                self.runtime,
                self.app,
                disclosure,
                approved_destination=destination,
            )
        ]
        if self.fixture.member.state.being_ref in disclosure["participants"]:
            other, other_app = self.member_application()
            bindings.append(
                accept_group_visibility(
                    other,
                    other_app,
                    disclosure,
                    approved_destination=destination,
                )
            )
        return disclosure, bindings

    def initial_visibility(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration = self.visibility_configuration()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        result = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=None,
            initial_configuration=configuration,
        )
        return installation, configuration, result

    def test_initial_and_expanded_visibility_preserve_keys_qualification_and_retry(
        self,
    ):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        previous = json.loads(installation.read_bytes())
        key_files = {
            name: (
                (installation.parent / name).stat().st_ino,
                (installation.parent / name).read_bytes(),
            )
            for name in ("telegram.token", "proof.key")
        }
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        result = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        selected = json.loads(installation.read_bytes())
        self.assertEqual(selected["document"]["generation"], 2)
        self.assertEqual(
            selected["document"]["secrets"], previous["document"]["secrets"]
        )
        self.assertEqual(
            selected["document"]["telegram_qualification"],
            previous["document"]["telegram_qualification"],
        )
        for name, (inode, raw) in key_files.items():
            self.assertEqual((installation.parent / name).stat().st_ino, inode)
            self.assertEqual((installation.parent / name).read_bytes(), raw)
        self.assertEqual(len(selected["document"]["acceptance_set"]["bindings"]), 2)
        retry = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        self.assertEqual(retry, {**result, "status": "current"})
        self.assertEqual(json.loads(installation.read_bytes()), selected)

    def test_visibility_lost_selection_reply_recovers_original_generation(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        replace_file = os.replace

        def lost(source, destination):
            replace_file(source, destination)
            if Path(destination) == installation:
                raise OSError("lost visibility publication reply")

        with (
            patch("daimon_matrix.operator_messaging.os.replace", side_effect=lost),
            self.assertRaises(OSError),
        ):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=initial["installation_sha256"],
            )
        before = installation.read_bytes()
        recovered = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        self.assertEqual(recovered["status"], "current")
        self.assertEqual(installation.read_bytes(), before)
        self.assertEqual(json.loads(before)["document"]["generation"], 2)

    def test_visibility_parent_sync_precedes_selection_and_retry_recovers(self):
        from daimon_matrix.operator_messaging import _sync, publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        original = installation.read_bytes()

        def lost_parent_sync(directory):
            _sync(directory)
            if directory == installation.parent:
                self.assertEqual(installation.read_bytes(), original)
                raise OSError("lost parent directory sync acknowledgment")

        with (
            patch(
                "daimon_matrix.operator_messaging._sync", side_effect=lost_parent_sync
            ),
            self.assertRaises(OSError),
        ):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=initial["installation_sha256"],
            )
        self.assertEqual(installation.read_bytes(), original)
        result = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        self.assertEqual(result["status"], "group-visibility-selected")
        self.assertEqual(
            json.loads(installation.read_bytes())["document"]["generation"], 2
        )

    def test_visibility_rejected_predecessor_does_not_poison_exact_retry(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        original = installation.read_bytes()
        damaged = json.loads(original)
        damaged["binding"]["signature"] = "tampered"
        installation.write_bytes(canonical_bytes(damaged))
        operations = set(installation.parent.glob(".group-visibility-*"))
        with self.assertRaises(ValueError):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=initial["installation_sha256"],
            )
        self.assertEqual(
            set(installation.parent.glob(".group-visibility-*")), operations
        )
        installation.write_bytes(original)
        result = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        self.assertEqual(result["status"], "group-visibility-selected")

    def test_visibility_rejected_initial_config_does_not_poison_exact_retry(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration = self.visibility_configuration()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        damaged = copy.deepcopy(configuration)
        damaged["secrets"]["telegram_token_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=None,
                initial_configuration=damaged,
            )
        self.assertFalse(installation.exists())
        self.assertEqual(list(installation.parent.glob(".group-visibility-*")), [])
        result = publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=None,
            initial_configuration=configuration,
        )
        self.assertEqual(result["status"], "group-visibility-selected")

    def test_visibility_missing_acceptance_preserves_the_selected_predecessor(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        before = installation.read_bytes()
        with self.assertRaisesRegex(ValueError, "acceptance_missing"):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings[:1],
                expected_installation_sha256=initial["installation_sha256"],
            )
        self.assertEqual(installation.read_bytes(), before)

    def test_visibility_retry_does_not_overwrite_a_later_signed_generation(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration, initial = self.initial_visibility()
        self.accept()
        self.publish()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        publish_group_visibility(
            self.runtime,
            self.app,
            installation,
            disclosure,
            bindings,
            expected_installation_sha256=initial["installation_sha256"],
        )
        # A separately selected, valid owner-signed installation has won since
        # this retained admission. Its current generation must never roll back.
        later = json.loads(installation.read_bytes())["document"]
        later["generation"] += 1
        later["policy"]["generation"] += 1
        winner = canonical_bytes(
            {
                "document": later,
                "binding": create_binding(self.runtime, later),
            }
        )
        installation.write_bytes(winner)
        with self.assertRaisesRegex(ValueError, "group_visibility_conflict"):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=initial["installation_sha256"],
            )
        self.assertEqual(installation.read_bytes(), winner)

    def test_initial_visibility_rejects_escaping_secret_paths_before_reading(self):
        from daimon_matrix.operator_messaging import publish_group_visibility

        installation, configuration = self.visibility_configuration()
        disclosure, bindings = self.accepted_disclosure(configuration["destination"])
        configuration["secrets"]["proof_key_file"] = "../private.key"
        with (
            patch(
                "daimon_matrix.operator_messaging.protected_read",
                side_effect=AssertionError("unsafe reference reached a private read"),
            ),
            self.assertRaisesRegex(ValueError, "group_visibility_conflict"),
        ):
            publish_group_visibility(
                self.runtime,
                self.app,
                installation,
                disclosure,
                bindings,
                expected_installation_sha256=None,
                initial_configuration=configuration,
            )
        self.assertFalse(installation.exists())

    def test_disclosure_refuses_a_stale_application_audience(self):
        from daimon_matrix.operator_messaging import group_visibility_disclosure

        self.accept()
        with self.assertRaisesRegex(ValueError, "group_visibility_context_rejected"):
            group_visibility_disclosure(
                self.runtime,
                self.app,
                approved_destination={
                    "bot_id": 137,
                    "chat_id": -100137,
                    "topic_id": None,
                    "representation": "compact-html/v1",
                },
                issued_at_ms=self.fixture.now,
            )

    def test_admission_cannot_replace_routes_client_stores_or_approved_addition(self):
        self.accept()
        original = copy.deepcopy(self.candidate)
        cases = (
            ("authorities", list(reversed(self.candidate["authorities"]))),
            ("roster", [self.candidate["roster"][1]]),
            ("stores", {**self.candidate["stores"], "records": "other.sqlite"}),
            ("client", {**self.candidate["client"], "secret_sha256": "0" * 64}),
            ("relationship_events", self.candidate["relationship_events"][1:]),
        )
        for name, value in cases:
            self.candidate = {**original, name: value}
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.publish()
        self.candidate = original
        with self.assertRaises(ValueError):
            self.publish(admitted_being_refs=[self.fixture.founder.state.being_ref])
        with self.assertRaises(ValueError):
            self.publish(expected_application_sha256="0" * 64)
        self.assertEqual(read_publication(self.runtime, self.app)[0], self.previous)


class PublicAuthorityHistoryTests(unittest.TestCase):
    def setUp(self):
        from tests.test_dm022_ledger import RootLedgerFixture

        self.fixture = RootLedgerFixture()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def restart(self):
        from daimon_matrix.authority_epochs import create_authority_epoch
        from daimon_matrix.identity import create_incarnation_authorization
        from tests.test_dm022_ledger import NOW

        fixture = self.fixture
        credential = next(
            value
            for value in fixture.credentials.values()
            if value["body"]["embodiment_id"] == "embodiment:legion"
        )
        incarnation = create_incarnation_authorization(
            credential,
            fixture.signing_seeds["legion"],
            incarnation_id="incarnation:legion:1",
            incarnation_sequence=1,
            started_at_ms=NOW + 1,
        )
        manifest = copy.deepcopy(dict(fixture.manifest.value))
        manifest["revision"] += 1
        for row in manifest["embodiments"]:
            if row["embodiment_id"] == "embodiment:legion":
                row["status"] = "retired"
                manifest["embodiments"].append(
                    {
                        **row,
                        "status": "active",
                        "incarnation_id": "incarnation:legion:1",
                        "incarnation_authorization_id": incarnation["artifact_id"],
                    }
                )
                break
        manifest["embodiments"].sort(
            key=lambda row: (row["embodiment_id"], row["incarnation_id"])
        )
        from daimon_matrix.weave import BeingManifest

        successor = create_authority_epoch(
            fixture.manifest,
            BeingManifest.from_value(manifest),
            embodiment_id="embodiment:legion",
            previous_incarnation_id="incarnation:legion:0",
            successor_authorization=incarnation,
            signing_seed=fixture.signing_seeds["legion"],
            issued_at_ms=NOW + 1,
        )
        previous = {
            "schema": "dm.operator.authority/v1",
            "control_artifacts": [fixture.genesis],
            "control_head": fixture.state.head,
            "manifest": fixture.manifest.value,
            "credentials": list(fixture.credentials.values()),
            "incarnations": list(fixture.incarnations.values()),
        }
        current = {
            **previous,
            "manifest": manifest,
            "incarnations": [*previous["incarnations"], incarnation],
        }
        history = [
            {
                **{key: value for key, value in previous.items() if key != "schema"},
                "successor": successor,
            }
        ]
        return previous, current, history

    def test_public_history_verifies_historical_event_without_foreign_ledger(self):
        from daimon_matrix.operator_messaging import public_authority_history
        from daimon_matrix.weave import verify_event

        _, current, history = self.restart()
        event = self.fixture.append(self.fixture.ledger_a, "legion", "old-proof")
        inputs = copy.deepcopy((current, history))
        authority = public_authority_history(current, history)
        self.assertEqual(authority.historical[0], self.fixture.authority)
        verify_event(event, authority)
        self.assertEqual((current, history), inputs)
        self.assertEqual(authority.active.manifest.value, current["manifest"])

    def test_compact_native_restart_history_uses_the_same_validator(self):
        from daimon_matrix.operator_messaging import public_authority_history
        from daimon_matrix.weave import verify_event

        _, current, history = self.restart()
        compact = [
            {"manifest": row["manifest"], "successor": row["successor"]}
            for row in history
        ]
        authority = public_authority_history(current, compact)
        event = self.fixture.append(self.fixture.ledger_a, "legion", "old-proof")
        verify_event(event, authority)

    def test_public_history_rejects_forged_reordered_and_substituted_epochs(self):
        from daimon_matrix.operator_messaging import public_authority_history

        previous, current, history = self.restart()
        forged = copy.deepcopy(history)
        forged[0]["successor"]["signature"]["value"] = b64url(bytes(64))
        for document, epochs in (
            (current, forged),
            (previous, history),
            (current, history * 2),
            (current, history * 257),
            (current, [{**history[0], "unexpected": True}]),
            (current, [None]),
            (current, "not-a-history"),
        ):
            with self.subTest(epochs=str(epochs)[:50]), self.assertRaises(ValueError):
                public_authority_history(document, epochs)

    def test_empty_history_does_not_invent_an_older_epoch(self):
        from daimon_matrix.operator_messaging import public_authority_history

        _, current, _ = self.restart()
        authority = public_authority_history(current, [])
        self.assertEqual(authority.historical, [])
        self.assertEqual(
            authority.accepted_manifest_hashes, (authority.manifest.digest,)
        )


class ForeignAuthorityAdoptionTests(unittest.TestCase):
    def test_real_foreign_ledger_and_current_local_keys_survive_signed_retirement(self):
        from daimon_matrix.authority_epochs import create_embodiment_retirement
        from daimon_matrix.identity import create_revocation, verify_successor
        from daimon_matrix.messaging_config import verify_binding
        from daimon_matrix.native_egress import closed_visibility
        from daimon_matrix.operator_messaging import (
            adopt_peer_authority,
            known_peer_successor,
        )
        from daimon_matrix.runtime import load_runtime
        from daimon_matrix.weave import BeingManifest, RootAuthority
        from tests.test_dm022_ledger import NOW, RootLedgerFixture
        from tests.test_dm024_runtime import PASSWORD

        runtime, _, _, _ = application_fixture(self)
        foreign = RootLedgerFixture()
        foreign.setUp()
        self.addCleanup(foreign.tearDown)
        before_authority = {
            "schema": "dm.operator.authority/v1",
            "control_artifacts": [foreign.genesis],
            "control_head": foreign.state.head,
            "manifest": foreign.manifest.value,
            "credentials": list(foreign.credentials.values()),
            "incarnations": list(foreign.incarnations.values()),
        }
        known = {
            key: value for key, value in before_authority.items() if key != "schema"
        }
        known.update(authority_history=[], ledger_filename="foreign.sqlite")
        bundle = json.loads((runtime.state_root / "runtime.json").read_bytes())
        bundle["sources"] = {"cas_filename": "sources.sqlite", "known_beings": [known]}
        (runtime.state_root / "runtime.json").write_bytes(canonical_bytes(bundle))
        before = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW + 30,
            egress=closed_visibility(clock=lambda: NOW + 30, catalog_mode="migrate"),
        )
        foreign_ledger = before.service.sources.registry.known_ledgers[
            foreign.state.being_ref
        ]
        event = foreign_ledger.append_local(
            kind="experience.observed",
            subject="retained",
            payload={"summary": "retained"},
            signer=foreign.signers["daimonmatrix"],
            occurred_at_ms=NOW,
        )
        custody = (runtime.state_root / "custody.json").read_bytes()
        control = create_revocation(
            foreign.state,
            foreign.root_seeds,
            embodiment_id="embodiment:daimonmatrix",
            revocation_generation=1,
            cutoff_incarnation_sequence=0,
        )
        state = verify_successor(control, foreign.state)
        value = copy.deepcopy(dict(foreign.manifest.value))
        value.update(control_head=state.head, revision=2)
        for row in value["embodiments"]:
            if row["embodiment_id"] == "embodiment:daimonmatrix":
                row["status"] = "retired"
        active = RootAuthority(
            BeingManifest.from_value(value),
            state,
            foreign.credentials,
            foreign.incarnations,
        )
        transition = create_embodiment_retirement(
            foreign.manifest,
            active.manifest,
            revocations=[control],
            root_seeds=foreign.root_seeds,
            issued_at_ms=NOW + 10,
        )
        public = {
            **before_authority,
            "manifest": value,
            "control_head": state.head,
            "control_artifacts": [foreign.genesis, control],
        }
        history = [
            {
                **{
                    key: value
                    for key, value in before_authority.items()
                    if key != "schema"
                },
                "successor": transition,
            }
        ]
        invalid = copy.deepcopy(history)
        invalid[0]["successor"]["signatures"] = []
        with self.assertRaises(ValueError):
            adopt_peer_authority(before, public, invalid)
        self.assertEqual(
            json.loads((runtime.state_root / "runtime.json").read_bytes()), bundle
        )
        replace = os.replace

        def fail_bundle_switch(source, destination):
            if Path(destination) == runtime.state_root / "runtime.json":
                raise OSError("interrupted before bundle selection")
            return replace(source, destination)

        with (
            patch(
                "daimon_matrix.operator_messaging.os.replace",
                side_effect=fail_bundle_switch,
            ),
            self.assertRaises(OSError),
        ):
            adopt_peer_authority(before, public, history)
        self.assertEqual(
            json.loads((runtime.state_root / "runtime.json").read_bytes()), bundle
        )
        later = foreign_ledger.append_local(
            kind="experience.observed",
            subject="received-between-attempts",
            payload={"summary": "retained after interruption"},
            signer=foreign.signers["daimonmatrix"],
            occurred_at_ms=NOW + 1,
        )
        receipt = adopt_peer_authority(before, public, history)
        verify_binding(before, receipt["document"], receipt["binding"])
        after = load_runtime(
            runtime.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW + 30,
            egress=closed_visibility(clock=lambda: NOW + 30, catalog_mode="migrate"),
        )
        selected = after.service.sources.registry.known_ledgers[foreign.state.being_ref]
        self.assertEqual(selected.known_page(cursor=None)["events"], [event, later])
        selected.integrity_check()
        self.assertEqual((runtime.state_root / "custody.json").read_bytes(), custody)
        candidate = json.loads((runtime.state_root / "runtime.json").read_bytes())
        self.assertEqual(
            {k: v for k, v in candidate.items() if k != "sources"},
            {k: v for k, v in bundle.items() if k != "sources"},
        )
        files = sorted(path.name for path in runtime.state_root.iterdir())
        self.assertEqual(
            adopt_peer_authority(after, public, history)["status"], "current"
        )
        self.assertEqual(
            sorted(path.name for path in runtime.state_root.iterdir()), files
        )
        with self.assertRaises(ValueError):
            known_peer_successor(
                candidate["sources"]["known_beings"][0], before_authority, []
            )
