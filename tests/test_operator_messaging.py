"""Provisioning negative controls and operator entrypoint; no live enrollment."""

import contextlib
import copy
import io
import json
import os
import unittest
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.messaging_config import load_application
from daimon_matrix.operator_messaging import prepare
from tests.test_messaging_runtime import application_fixture


class ProvisioningTests(unittest.TestCase):
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

    def test_operator_renewal_preserves_stores_and_refuses_stale_predecessor(self):
        from daimon_matrix import operator_messaging as operator
        from daimon_matrix.messaging_config import config_digest, read_document

        runtime, spec, sources, _ = application_fixture(self)
        target = self.root / "app"
        create = operator.create_capability

        def short_capability(*args, **kwargs):
            kwargs["not_after_ms"] = kwargs["not_before_ms"] + 1
            return create(*args, **kwargs)

        with patch.object(operator, "create_capability", side_effect=short_capability):
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
        with self.assertRaises(ValueError):
            load_application(runtime, target)
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

        runtime, spec, _sources, _reads = application_fixture(self)
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
        self.pair.now += 1
        result, output, errors = call(
            "renew", ["--expected-application-sha256", predecessor]
        )
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(output)["status"], "renewed")
        digest = json.loads(output)["application_sha256"]
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
        (target / "client.key").write_bytes(b"PRIVATE-LEAK-SENTINEL-123456789012")
        result, output, errors = call("diagnostics")
        self.assertEqual(result, 1)
        self.assertNotIn("PRIVATE-LEAK", output + errors)
        self.assertNotIn(PASSWORD.decode(), output + errors)
        self.assertNotIn("Traceback", errors)

    def test_run_entrypoint_real_child_binds_both_transports_and_stops(self):
        import select
        import socket
        import subprocess
        import sys

        from tests.test_dm024_runtime import PASSWORD

        runtime, spec, sources, _ = application_fixture(self)
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
            self.assertTrue(os.read(readyread, 4096), "child exited without readiness")
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
