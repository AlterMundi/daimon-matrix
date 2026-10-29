"""Process-local receiver selection uses the real native physical-write fence."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import closing, contextmanager, nullcontext, suppress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import ClientError
from daimon_matrix.local_api import (
    LocalApiError,
    create_capability,
    create_request,
    request_hash,
)
from daimon_matrix.messaging_store import TribeRecordStore
from daimon_matrix.native_egress import NativeEgressError, synthetic_visibility
from daimon_matrix.release_compatibility import describe_reader
from daimon_matrix.runtime import RuntimeError as RuntimeLoadError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import (
    HostedWeave,
    MessagingServiceContext,
    ReceivingServiceContext,
    ServiceError,
)
from tests import test_dm025_client as client_fixtures
from tests import test_group_messaging_runtime as group_fixtures
from tests.reader_fixtures import reader, reader_v2


def budget():
    return time.monotonic_ns() + 5_000_000_000


def command(controller, *, phase="revoke", readers=None, operation_id=None, **changes):
    current = controller.reader_snapshot("tribe", deadline_ns=budget())
    return {
        **(
            {"schema": "dm.runtime.reader-selection/v2"}
            if readers
            and any(row.get("schema") == "dm.receiving.reader/v2" for row in readers)
            else {}
        ),
        "process_instance_id": current["process_instance_id"],
        "channel_id": "tribe",
        "expected_head": current["head"],
        "operation_id": operation_id or current["operation_id"] or str(uuid.uuid4()),
        "release_digest": "a" * 64,
        "phase": phase,
        "readers": readers or [],
        **changes,
    }


def select(controller, value, request=None):
    # Stand in only for an authenticated request's digest, never for the fence
    # or receiving behavior. The owner RPC boundary is qualified separately.
    request = request or hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    return controller.select_readers(
        value, request_sha256=request, deadline_ns=budget()
    )


class ReceivingOwnerConnectionTests(client_fixtures.ClientFixture):
    def test_owner_startup_handoff_freezes_evidence_and_rejects_context_drift(self):
        # Pure loader seam qualification; the actual closed-interpreter
        # bootstrap is separately exercised by Cluster's subprocess fixture.
        startup_sys = SimpleNamespace(
            flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1),
            path=list(sys.path),
            dont_write_bytecode=True,
            pycache_prefix="/synthetic-closed-tree/.disabled-bytecode",
            implementation=sys.implementation,
            version_info=sys.version_info,
        )
        context = {
            "path": startup_sys.path,
            "dont_write_bytecode": startup_sys.dont_write_bytecode,
            "pycache_prefix": startup_sys.pycache_prefix,
        }
        observation = {
            "schema": "cluster-onboarding-loaded-startup/v1",
            "process_id": os.getpid(),
            "startup_instance_id": str(uuid.uuid4()),
            "matrix_commit": "a" * 40,
            **{
                field: "a" * 64
                for field in (
                    "code_digest",
                    "sdk_digest",
                    "matrix_wheel_sha256",
                    "import_files_sha256",
                )
            },
            "import_context_sha256": hashlib.sha256(
                json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "interpreter": {
                "implementation": sys.implementation.name,
                "version": list(sys.version_info[:3]),
                "executable_sha256": hashlib.sha256(
                    Path("/proc/self/exe").read_bytes()
                ).hexdigest(),
            },
            "reader": describe_reader(),
            "isolated": True,
            "no_site": True,
            "no_bytecode": True,
        }
        with patch("daimon_matrix.runtime.sys", startup_sys):
            hosted = load_runtime(
                self.state_root,
                "runtime.json",
                lambda: bytearray(client_fixtures.PASSWORD),
                clock=self.client().clock,
                qualified_startup=observation,
            )
            frozen = json.loads(hosted.service.loaded_runtime)["qualified_startup"]
            observation["sdk_digest"] = "f" * 64
            self.assertEqual(
                json.loads(hosted.service.loaded_runtime)["qualified_startup"], frozen
            )
            for field, changed in (
                ("path", [*startup_sys.path, "/unqualified-extra"]),
                ("dont_write_bytecode", False),
                ("pycache_prefix", "/unqualified-cache"),
                ("version_info", (0, 0, 0)),
            ):
                with (
                    self.subTest(field=field),
                    patch.object(startup_sys, field, changed),
                    self.assertRaisesRegex(
                        RuntimeLoadError, "qualified_startup_rejected"
                    ),
                ):
                    load_runtime(
                        self.state_root,
                        "runtime.json",
                        lambda: self.fail("context drift must reject before custody"),
                        clock=self.client().clock,
                        qualified_startup=observation,
                    )

    def test_qualification_from_another_process_is_rejected_before_custody(self):
        with self.assertRaisesRegex(RuntimeLoadError, "qualified_startup_rejected"):
            load_runtime(
                self.state_root,
                "runtime.json",
                lambda: self.fail("a parent observation cannot unlock custody"),
                clock=self.client().clock,
                qualified_startup={
                    "schema": "cluster-onboarding-loaded-startup/v1",
                    "process_id": os.getpid() + 1,
                    "startup_instance_id": str(uuid.uuid4()),
                    "matrix_commit": "a" * 40,
                    **{
                        field: "a" * 64
                        for field in (
                            "code_digest",
                            "sdk_digest",
                            "matrix_wheel_sha256",
                            "import_files_sha256",
                            "import_context_sha256",
                        )
                    },
                    "isolated": True,
                    "no_site": True,
                    "no_bytecode": True,
                    "interpreter": {},
                    "reader": {},
                },
            )

    def test_loaded_runtime_snapshot_ignores_new_disk_selection_and_reconciles_restart(
        self,
    ):
        client = self.client()
        request, response = client.runtime_status()
        loaded = response["result"]["loaded_runtime"]
        self.assertEqual(loaded["process_id"], os.getpid())
        self.assertIsNone(loaded["qualified_startup"])
        bundle_path = self.state_root / "runtime.json"
        bundle = json.loads(bundle_path.read_bytes())
        self.assertEqual(
            loaded["runtime_bundle_sha256"],
            hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
        )
        bundle["socket"] = "selected-not-loaded.sock"
        bundle_path.write_bytes(canonical_bytes(bundle))
        # The old process must report what it actually loaded, not the selector
        # now on disk. Mutating a returned snapshot cannot change that fact.
        loaded["runtime_bundle_sha256"] = "f" * 64
        old = client.send(request)["result"]["loaded_runtime"]
        self.assertNotEqual(
            old["runtime_bundle_sha256"], loaded["runtime_bundle_sha256"]
        )
        restarted = load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(client_fixtures.PASSWORD),
            clock=client.clock,
        )
        current = restarted.service.handle(request)["result"]["loaded_runtime"]
        self.assertNotEqual(current["process_instance_id"], old["process_instance_id"])
        self.assertNotEqual(
            current["runtime_bundle_sha256"], old["runtime_bundle_sha256"]
        )
        self.assertEqual(
            current["runtime_bundle_sha256"],
            hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
        )

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Linux peer credentials")
    def test_observer_pins_the_actual_authenticated_status_connection(self):
        order = []
        checked = []
        from daimon_matrix.client import verify_response

        def authenticate(*args, **kwargs):
            value = verify_response(*args, **kwargs)
            checked.append(value)
            order.append("authenticated")
            return value

        @contextmanager
        def observe(connection):
            pid, uid, _gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            self.assertEqual((pid, uid), (os.getpid(), os.geteuid()))
            order.append("connected")
            yield
            self.assertGreaterEqual(connection.fileno(), 0)
            self.assertEqual(len(checked), 1)
            order.append("verified")

        client = replace(self.client(), connection_observer=observe)
        with patch("daimon_matrix.client.verify_response", side_effect=authenticate):
            _, response = client.runtime_status()
        self.assertTrue(response["ok"])
        self.assertEqual(order, ["connected", "authenticated", "verified"])

    def mutation(self):
        return self.client().prepare(
            "we.observe",
            {
                "subject": "connected-owner-observation",
                "payload": {"summary": "owner observer failure may follow an effect"},
                "sensitivity": "personal",
                "causal_parents": [],
                "occurred_at_ms": self.client().clock(),
                "event_id": None,
            },
        )

    def test_observer_refusal_before_write_does_not_submit_the_request(self):
        @contextmanager
        def refuse(_connection):
            raise RuntimeError("synthetic owner refusal")
            yield

        with self.assertRaisesRegex(ClientError, "daemon_observation_rejected"):
            replace(self.client(), connection_observer=refuse).send(self.mutation())
        self.assertEqual(self.runtime.service.ledger.events(), [])
        self.assertEqual(self.runtime.service.ledger.status_counts()["pending_rpc"], 0)

    def test_observer_failure_after_effect_preserves_exact_retry_and_history(self):
        @contextmanager
        def fail_after_authentication(_connection):
            yield
            raise RuntimeError("synthetic process observation lost after effect")

        request = self.mutation()
        with self.assertRaisesRegex(ClientError, "daemon_observation_rejected"):
            replace(self.client(), connection_observer=fail_after_authentication).send(
                request
            )
        self.assertEqual(len(self.runtime.service.ledger.events()), 1)
        current = self.client().send(request)
        self.assertTrue(current["ok"])
        self.assertEqual(self.client().send(request), current)
        self.assertEqual(len(self.runtime.service.ledger.events()), 1)

    def test_observer_cannot_suppress_failed_response_authentication(self):
        @contextmanager
        def suppress_failure(_connection):
            with suppress(ClientError):
                yield

        client = self.client()
        client = replace(
            client,
            config=replace(client.config, runtime_id="dm:runtime:v1:" + "B" * 43),
            connection_observer=suppress_failure,
        )
        with self.assertRaisesRegex(ClientError, "daemon_response_rejected"):
            client.runtime_status()


class ReceivingOwnerApiFixture(unittest.TestCase):
    controlled_readers = True

    def setUp(self):
        group_fixtures.GroupRuntimeTests.setUp(self)
        self.group = self.groups[0]
        self.controller = create_capability(
            b"c" * 32,
            client_id="client:host:synthetic:receiving-controller",
            methods=["runtime.reader-selection"],
            not_before_ms=0,
            not_after_ms=2**53 - 1,
        )
        self.observer = create_capability(
            b"s" * 32,
            client_id="client:host:synthetic:status",
            methods=["runtime.status"],
            not_before_ms=0,
            not_after_ms=2**53 - 1,
        )
        self.messaging = MessagingServiceContext(
            channels={"tribe": self.group},
            deliveries={"tribe": self.group},
            client_channels={},
        )
        self.service = self.build(self.group)

    def build(self, group):
        return HostedWeave(
            group.ledger,
            group.signer,
            {cap.capability_id: cap for cap in (self.controller, self.observer)},
            group.lane.clock,
            "dm:runtime:v1:" + "A" * 43,
            "synthetic",
            communication=group.communication,
            messaging=replace(
                self.messaging,
                channels={"tribe": group},
                deliveries={"tribe": group},
            ),
            receiving=ReceivingServiceContext(
                self.controller.capability_id, {"tribe": group}
            ),
        )

    def request(self, params, *, method="runtime.reader-selection", capability=None):
        return create_request(
            capability or self.controller,
            request_id=str(uuid.uuid4()),
            issued_at_ms=self.fixture.now,
            method=method,
            params=params,
        )

    def credential_reader(self):
        authority = self.group.lane.authority
        credential_id = self.group.lane.local_credential_id
        body = authority.credentials[credential_id]["body"]
        member = next(
            row
            for row in authority.manifest.value["embodiments"]
            if row["embodiment_credential_id"] == credential_id
        )
        return reader_v2(
            being_ref=authority.manifest.being_ref,
            embodiment_id=member["embodiment_id"],
            incarnation_id=member["incarnation_id"],
            credential_id=credential_id,
            authority_manifest_hash=authority.manifest.digest,
            authority_epochs=[authority.manifest.digest],
            validity=body.get(
                "validity",
                {
                    "mode": "finite",
                    "not_before_ms": body.get("valid_from_ms"),
                    "not_after_ms": body.get("valid_until_ms"),
                },
            ),
        )


class ReceivingOwnerApiTests(ReceivingOwnerApiFixture):
    def test_credential_bound_finite_selection_refuses_broader_validity(self):
        row = self.credential_reader()
        self.assertEqual(row["validity"]["mode"], "finite")
        roster = self.group.receiving_roster()["roster_sha256"]
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        broad = {**row, "validity": {"mode": "until-revoked", "not_before_ms": 0}}
        refused = self.service.handle(
            self.request(
                command(
                    self.group.egress,
                    phase="select",
                    readers=[broad],
                    expected_roster_sha256=roster,
                )
            )
        )
        self.assertEqual(refused["error"]["code"], "reader_validity_conflict")
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[row],
                expected_roster_sha256=roster,
            )
        )
        result = self.service.handle(request)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["schema"], "dm.receiving.reader-selection/v2")
        self.assertEqual(self.service.handle(request), result)
        self.fixture.now = row["validity"]["not_after_ms"]
        self.assertFalse(self.group.egress.reader_ready("tribe", row))

    def test_typed_control_is_explicit_and_legacy_shape_stays_closed(self):
        row = self.credential_reader()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        before = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        typed = command(
            self.group.egress,
            phase="select",
            readers=[row],
            expected_roster_sha256=self.group.receiving_roster()["roster_sha256"],
        )
        for invalid in (
            {k: v for k, v in typed.items() if k != "schema"},
            {**typed, "schema": "dm.runtime.reader-selection/v3"},
            {**typed, "readers": [reader()]},
        ):
            with self.subTest(schema=invalid.get("schema")):
                result = self.service.handle(self.request(invalid))
                self.assertEqual(result["error"]["code"], "reader_selection_invalid")
                self.assertEqual(
                    self.group.egress.reader_snapshot("tribe", deadline_ns=budget()),
                    before,
                )

    def test_credential_bound_control_requires_roster_before_native_selection(self):
        row = self.credential_reader()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        before = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        refused = self.service.handle(
            self.request(
                command(
                    self.group.egress,
                    phase="select",
                    readers=[row],
                )
            )
        )
        self.assertEqual(refused["error"]["code"], "reader_roster_required")
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget()), before
        )

    def test_roster_digest_is_stable_across_clock_and_contains_verified_proof_epochs(
        self,
    ):
        first = self.group.receiving_roster()
        self.fixture.now += 1
        later = self.group.receiving_roster()
        self.assertEqual(first["roster_sha256"], later["roster_sha256"])
        self.assertNotEqual(first["evaluated_at_ms"], later["evaluated_at_ms"])
        self.assertEqual(len(first["audience"]), 2)
        required = set(first["required_authority_epochs"])
        self.assertTrue(
            {row["authority_manifest_hash"] for row in first["audience"]} <= required
        )
        self.assertTrue(
            {row["signer_manifest_hash"] for row in first["membership_proofs"]}
            <= required
        )
        self.assertNotIn("grants", first)
        self.assertNotIn("events", first)

    def test_current_roster_select_and_exact_retry_use_existing_control(self):
        roster = self.group.receiving_roster()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                expected_roster_sha256=roster["roster_sha256"],
            )
        )
        response = self.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(self.service.handle(request), response)
        status = self.service.handle(
            self.request({}, method="runtime.status", capability=self.observer)
        )
        self.assertEqual(
            status["result"]["receiving"]["rosters"]["tribe"]["roster_sha256"],
            roster["roster_sha256"],
        )

    def test_signed_membership_change_refuses_old_roster_without_enabling_readers(self):
        from daimon_matrix.relationships import MEMBERSHIP_LEAVE_SCHEMA

        roster = self.group.receiving_roster()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        old_request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                expected_roster_sha256=roster["roster_sha256"],
            )
        )
        member = self.fixture.member.state.being_ref
        acceptance = next(
            event
            for event in self.fixture.events
            if event["event_id"] == self.fixture._membership_of(member)
        )
        self.fixture.journey.append(
            "member",
            "matrix/tribe-membership-leave",
            dict(
                schema=MEMBERSHIP_LEAVE_SCHEMA,
                tribe_ref=self.fixture.tribe_ref,
                founder_epoch=self.group.lane.snapshot(
                    self.fixture.tribe_ref, self.fixture.now
                ).value["founder_epoch"],
                member_being_ref=member,
                membership_acceptance_ref=dict(
                    event_id=acceptance["event_id"],
                    event_hash=acceptance["content_hash"],
                ),
                reason="synthetic-roster-CAS",
                terminated_at_ms=self.fixture.now,
            ),
            at_ms=self.fixture.now,
        )
        from daimon_matrix.relationship_store import RelationshipStoreError

        with self.assertRaises(RelationshipStoreError):
            self.group.receiving_roster()
        rejected = self.service.handle(old_request)
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"], "reader_roster_unavailable")
        gate = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        self.assertEqual((gate["phase"], gate["readers"]), ("revoke", []))
        # Emergency revocation is available even while the roster differs.
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        status = self.service.handle(
            self.request({}, method="runtime.status", capability=self.observer)
        )
        self.assertTrue(status["ok"], status)
        self.assertEqual(
            status["result"]["receiving"]["rosters"]["tribe"]["schema"],
            "dm.runtime.tribe-roster-unavailable/v1",
        )
        self.assertEqual(
            status["result"]["receiving"]["channels"]["tribe"]["phase"], "revoke"
        )

    def test_roster_transaction_is_held_through_local_select_and_never_waits_for_writer(
        self,
    ):
        roster = self.group.receiving_roster()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        native = self.group.egress._select_readers_locked
        checked = []

        def locked(*args):
            acquisitions = []

            def contend():
                acquired = self.group.egress._fence.acquire(blocking=False)
                acquisitions.append(acquired)
                if acquired:
                    self.group.egress._fence.release()

            contender = threading.Thread(target=contend)
            contender.start()
            contender.join(1)
            self.assertFalse(contender.is_alive())
            self.assertEqual(acquisitions, [False])
            with (
                closing(
                    sqlite3.connect(self.group.lane.relationships.path, timeout=0)
                ) as writer,
                self.assertRaises(sqlite3.OperationalError),
            ):
                writer.execute("BEGIN IMMEDIATE")
            checked.append(True)
            return native(*args)

        with patch.object(
            self.group.egress, "_select_readers_locked", side_effect=locked
        ):
            selected = self.service.handle(
                self.request(
                    command(
                        self.group.egress,
                        phase="select",
                        readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                        expected_roster_sha256=roster["roster_sha256"],
                    )
                )
            )
        self.assertTrue(selected["ok"], selected)
        self.assertEqual(checked, [True, True])
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        with closing(
            sqlite3.connect(self.group.lane.relationships.path, timeout=0)
        ) as writer:
            writer.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            refused = self.service.handle(
                self.request(
                    command(
                        self.group.egress,
                        phase="select",
                        readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                        expected_roster_sha256=roster["roster_sha256"],
                    )
                )
            )
            self.assertLess(time.monotonic() - started, 1)
            self.assertFalse(refused["ok"])
            self.assertTrue(refused["error"]["retryable"])
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget())["phase"],
            "revoke",
        )

    def test_roster_opt_in_rejects_null_and_stale_digest_without_changing_gate(self):
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        before = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        for expected, error in (
            (None, "reader_selection_invalid"),
            ("f" * 64, "reader_roster_conflict"),
        ):
            rejected = self.service.handle(
                self.request(
                    command(
                        self.group.egress,
                        phase="select",
                        readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                        expected_roster_sha256=expected,
                    )
                )
            )
            self.assertFalse(rejected["ok"], rejected)
            self.assertEqual(rejected["error"]["code"], error)
            self.assertEqual(
                self.group.egress.reader_snapshot("tribe", deadline_ns=budget()), before
            )

    def test_cached_success_and_first_failure_return_bounded_roster_contention(self):
        roster = self.group.receiving_roster()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        selected_request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                expected_roster_sha256=roster["roster_sha256"],
            )
        )
        selected = self.service.handle(selected_request)
        self.assertTrue(selected["ok"], selected)
        status_request = self.request(
            {}, method="runtime.status", capability=self.observer
        )
        self.assertTrue(self.service.handle(status_request)["ok"])
        with closing(
            sqlite3.connect(self.group.lane.relationships.path, timeout=0)
        ) as writer:
            writer.execute("BEGIN IMMEDIATE")
            retried = self.service.handle(selected_request)
            self.assertFalse(retried["ok"], retried)
            self.assertEqual(
                retried["error"], dict(code="reader_roster_unavailable", retryable=True)
            )
            status = self.service.handle(status_request)
            self.assertTrue(status["ok"], status)
            self.assertEqual(
                status["result"]["receiving"]["rosters"]["tribe"]["schema"],
                "dm.runtime.tribe-roster-unavailable/v1",
            )
            self.assertTrue(
                status["result"]["receiving"]["rosters"]["tribe"]["retryable"]
            )
            self.assertEqual(
                status["result"]["receiving"]["channels"]["tribe"], selected["result"]
            )
        self.assertEqual(self.service.handle(selected_request), selected)

    def test_store_replaced_while_waiting_for_fence_cannot_acknowledge_selection(self):
        from daimon_matrix.service import LoadedStoreBinding

        path = self.group.lane.relationships.path
        self.group._loaded_store_bindings = (LoadedStoreBinding.capture(path),)
        roster = self.group.receiving_roster()
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60000)],
                expected_roster_sha256=roster["roster_sha256"],
            )
        )
        validated = threading.Event()
        original = self.group.validate

        def before_wait(service):
            original(service)
            validated.set()

        results = []
        self.group.egress._fence.acquire()
        worker = threading.Thread(
            target=lambda: results.append(self.service.handle(request))
        )
        with patch.object(self.group, "validate", side_effect=before_wait):
            try:
                worker.start()
                self.assertTrue(validated.wait(1))
                replacement = path.with_name(path.name + ".replacement")
                shutil.copy2(path, replacement)
                replacement.replace(path)
            finally:
                self.group.egress._fence.release()
                worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["ok"], results)
        gate = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        self.assertEqual((gate["phase"], gate["readers"]), ("revoke", []))

    def test_authenticated_control_current_retry_supersession_and_independent_status(
        self,
    ):
        with self.assertRaisesRegex(LocalApiError, "authentication_failed"):
            self.request(command(self.group.egress), capability=self.observer)
        revoke = self.request(command(self.group.egress))
        response = self.service.handle(revoke)
        self.assertTrue(response["ok"], response)
        self.assertEqual(self.service.handle(revoke), response)
        selected_request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        selected = self.service.handle(selected_request)
        self.assertTrue(selected["ok"], selected)
        self.assertEqual(self.service.handle(selected_request), selected)
        status = self.service.handle(
            self.request({}, method="runtime.status", capability=self.observer)
        )
        self.assertEqual(
            status["result"]["receiving"]["channels"]["tribe"], selected["result"]
        )
        self.assertEqual(selected["result"]["process_id"], os.getpid())
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        rejected = self.service.handle(selected_request)
        self.assertEqual(rejected["error"]["code"], "reader_selection_conflict")
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget())["readers"],
            [],
        )

    def test_pending_control_reconciles_applied_change_after_lost_rpc_completion(self):
        revoke = self.request(command(self.group.egress))
        self.assertTrue(self.service.handle(revoke)["ok"])
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        digest = request_hash(request)
        self.service.ledger.begin_rpc(
            client_id=self.controller.client_id,
            request_id=request["request_id"],
            request_hash=digest,
            method=request["method"],
        )
        applied = self.service._dispatch(
            request["method"],
            request["params"],
            client_id=self.controller.client_id,
            request_id=request["request_id"],
            request_hash=digest,
        )
        response = self.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"], applied)
        self.assertEqual(self.service.handle(request), response)

    def test_concurrent_revocation_before_rpc_completion_cannot_return_stale_enable(
        self,
    ):
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        request = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        finish = self.service.ledger.finish_rpc

        def revoke_before_completion(**arguments):
            select(self.group.egress, command(self.group.egress))
            return finish(**arguments)

        with patch.object(
            self.service.ledger, "finish_rpc", side_effect=revoke_before_completion
        ):
            response = self.service.handle(request)
        self.assertEqual(response["error"]["code"], "reader_selection_conflict")
        self.assertEqual(
            self.group.egress.reader_snapshot("tribe", deadline_ns=budget())["readers"],
            [],
        )

    def test_restart_never_reuses_completed_revoke_or_enable_as_current_control(self):
        revoke = self.request(command(self.group.egress))
        self.assertTrue(self.service.handle(revoke)["ok"])
        enabled = self.request(
            command(
                self.group.egress,
                phase="select",
                readers=[reader(expires_at_ms=self.fixture.now + 60_000)],
            )
        )
        self.assertTrue(self.service.handle(enabled)["ok"])
        status_request = self.request(
            {}, method="runtime.status", capability=self.observer
        )
        previous_status = self.service.handle(status_request)
        group = self.group
        fresh = type(group.egress)(
            policy=group.egress._policy,
            proof_key=group.egress._proof_key,
            transport=group.egress._transport,
            clock=group.lane.clock,
            catalog_mode="migrate",
        )
        restarted = group_fixtures.GroupMessaging(
            lane=group.lane,
            policy=group.policy,
            communication=group.communication,
            providers=group.providers,
            config_digest=group.config_digest,
            egress=fresh,
            controlled_readers=True,
        )
        service = self.build(restarted)
        current_status = service.handle(status_request)
        self.assertNotEqual(
            previous_status["result"]["receiving"],
            current_status["result"]["receiving"],
        )
        for retained in (revoke, enabled):
            response = service.handle(retained)
            self.assertEqual(response["error"]["code"], "reader_process_conflict")
        state = fresh.reader_snapshot("tribe", deadline_ns=budget())
        self.assertEqual(state["phase"], "unselected")
        self.assertEqual(state["readers"], [])

    def test_status_cached_in_controlled_view_never_claims_a_missing_current_context(
        self,
    ):
        request = self.request({}, method="runtime.status", capability=self.observer)
        previous = self.service.handle(request)
        self.assertIn("receiving", previous["result"])
        base_only = replace(self.service, receiving=None)
        current = base_only.handle(request)
        self.assertTrue(current["ok"], current)
        self.assertNotIn("receiving", current["result"])

    def test_owner_context_cannot_enable_an_ordinary_or_rebound_group(self):
        with self.assertRaisesRegex(ServiceError, "reader_controller_binding_invalid"):
            replace(
                self.service,
                receiving=ReceivingServiceContext(
                    self.observer.capability_id, {"tribe": self.group}
                ),
            )
        with self.assertRaises(TypeError):
            self.service.receiving.channels["tribe"] = self.groups[1]
        # A trusted compositor must bind the exact loaded group, not just its ID.
        with self.assertRaisesRegex(ServiceError, "reader_controller_binding_invalid"):
            replace(
                self.service,
                receiving=ReceivingServiceContext(
                    self.controller.capability_id, {"tribe": self.groups[1]}
                ),
            )


class UntilRevokedOwnerApiTests(ReceivingOwnerApiFixture):
    def setUp(self):
        from dataclasses import replace

        from daimon_matrix import identity
        from daimon_matrix.canonical import unb64url
        from daimon_matrix.synthetic_relationships import _identity, _seed
        from daimon_matrix.weave import BeingManifest, RootAuthority

        def signed_identity(label):
            old = _identity(label)
            body = old.credential["body"]
            credential = identity.create_embodiment_credential_v2(
                old.state,
                [_seed(f"{label}:root:{i}") for i in range(3)],
                _seed(f"{label}:signing"),
                unb64url(body["encryption_key"]["public"], length=32),
                embodiment_id=body["embodiment_id"],
                body_ref=body["body_ref"],
                purposes=body["purposes"],
                transport_principals=body["transport_principals"],
                validity={
                    "mode": "until-revoked",
                    "not_before_ms": body["valid_from_ms"],
                },
            )
            incarnation = identity.create_incarnation_authorization(
                credential,
                _seed(f"{label}:signing"),
                incarnation_id=old.origin["incarnation_id"],
                incarnation_sequence=0,
                started_at_ms=body["valid_from_ms"],
            )
            manifest = copy.deepcopy(dict(old.authority.manifest.value))
            manifest["embodiments"][0].update(
                embodiment_credential_id=credential["artifact_id"],
                incarnation_authorization_id=incarnation["artifact_id"],
            )
            authority = RootAuthority(
                BeingManifest.from_value(manifest),
                old.state,
                {credential["artifact_id"]: credential},
                {incarnation["artifact_id"]: incarnation},
            )
            return replace(old, credential=credential, authority=authority)

        with patch(
            "daimon_matrix.synthetic_relationships._identity",
            side_effect=signed_identity,
        ):
            super().setUp()

    def test_actual_signed_until_revoked_credential_accepts_typed_binding(self):
        row = self.credential_reader()
        self.assertEqual(row["validity"]["mode"], "until-revoked")
        self.assertTrue(
            self.service.handle(self.request(command(self.group.egress)))["ok"]
        )
        result = self.service.handle(
            self.request(
                command(
                    self.group.egress,
                    phase="select",
                    readers=[row],
                    expected_roster_sha256=self.group.receiving_roster()[
                        "roster_sha256"
                    ],
                )
            )
        )
        self.assertTrue(result["ok"], result)
        self.fixture.now += 1000
        self.assertTrue(self.group.egress.reader_ready("tribe", row))
        snapshot = self.group.egress.reader_snapshot("tribe", deadline_ns=budget())
        snapshot["readers"][0]["validity"]["not_before_ms"] = self.fixture.now + 1000
        row["validity"]["not_before_ms"] = self.fixture.now + 1000
        self.assertTrue(self.group.egress.reader_ready("tribe", row))


class ReceivingCompositionTests(unittest.TestCase):
    with_receiving_controller = True
    setUp = group_fixtures.GroupRuntimeTests.setUp

    def test_warm_reader_binding_rejects_clock_rollback_with_actual_verifier(self):
        from daimon_matrix.messaging_config import create_binding, verify_record_binding
        from tests.test_messaging_runtime import loaded

        _fixture, runtime, _reads = loaded(
            self, self.fixture.founder, clock=lambda: self.fixture.now
        )
        records = TribeRecordStore(
            runtime.state_root / "clock-regression.sqlite",
            sign=lambda value: create_binding(runtime, value),
            verify=lambda value, binding: verify_record_binding(
                runtime, value, binding
            ),
            clock=runtime.service.clock,
            cache_reader_bindings=True,
        )
        # Reuse an actual authenticated reader-control shape, without starting
        # a worker or producing any foreign message.
        helper = DurableReaderRecoveryTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        helper.records = records
        helper.enabled_v2()
        head = records.reader_control_head("tribe")
        now = self.fixture.now
        self.fixture.now = now - 1
        with self.assertRaisesRegex(ValueError, "messaging_binding_rejected"):
            records.reader_control_head("tribe")
        self.fixture.now = now
        self.assertEqual(records.reader_control_head("tribe"), head)

    def test_signed_composition_recovers_before_worker_start_and_invalidates_drift(
        self,
    ):
        from daimon_matrix.daemon import serve_forever
        from daimon_matrix.messaging import GroupMessaging

        _base, _app, initial = (
            group_fixtures.GroupRuntimeTests._signed_group_application(
                self, record_key_check=False
            )
        )

        def boot(view, *, publication=None):
            base = json.loads(view.service.loaded_runtime)
            base["process_instance_id"] = str(uuid.uuid4())
            base["qualified_startup"] = {
                "schema": "cluster-onboarding-loaded-startup/v1",
                "code_digest": "a" * 64,
                "sdk_digest": "b" * 64,
                "matrix_commit": "c" * 40,
                "matrix_wheel_sha256": "d" * 64,
                "import_context_sha256": "e" * 64,
                "import_files_sha256": "f" * 64,
                "interpreter": {"implementation": "cpython", "version": [3, 13, 5]},
                "reader": describe_reader(),
                "isolated": True,
                "no_site": True,
                "no_bytecode": True,
                "process_id": os.getpid(),
                "startup_instance_id": str(uuid.uuid4()),
            }
            app = json.loads(view.service.loaded_application)
            app["loaded_base_sha256"] = hashlib.sha256(
                canonical_bytes(base)
            ).hexdigest()
            if publication is not None:
                app["publication_sha256"] = publication
            app["loaded_view_sha256"] = hashlib.sha256(
                canonical_bytes(
                    {
                        k: v
                        for k, v in app.items()
                        if k not in {"loaded_view_sha256", "reader_gates"}
                    }
                )
            ).hexdigest()
            return replace(
                view,
                service=replace(
                    view.service,
                    loaded_runtime=canonical_bytes(base),
                    loaded_application=canonical_bytes(app),
                ),
            )

        class BeforeWorker(Exception):
            pass

        def start(view):
            # Reach the real common startup seam, then stop before worker or
            # socket creation. No model, Telegram request or transport replay.
            with (
                patch.object(view.egress, "worker_started", side_effect=BeforeWorker),
                self.assertRaises(BeforeWorker),
            ):
                serve_forever(view)

        first = boot(initial)
        start(first)
        group = first.service.receiving.channels["tribe"]
        controller = group.egress
        select(controller, command(controller))
        value = command(
            controller,
            phase="select",
            readers=[reader(expires_at_ms=self.fixture.now + 10_000)],
        )
        controller.select_readers(
            value,
            request_sha256="e" * 64,
            deadline_ns=budget(),
            recovery_roster_sha256=group.receiving_roster()["roster_sha256"],
        )

        def successor(previous, *, publication=None):
            current = type(controller)(
                policy=controller._policy,
                proof_key=controller._proof_key,
                transport=controller._transport,
                clock=group.lane.clock,
                catalog_mode="migrate",
                installation_digest=controller._installation_digest,
                owner_actor=controller._owner_actor,
                verify_owner_binding=controller._verify_owner_binding,
            )
            # Reuse the fixture's unchanged base catalog registrations; the
            # controlled group is reconstructed over its signed record store.
            current._catalogs = dict(controller._catalogs)
            current._paths = {
                key: set(value) for key, value in controller._paths.items()
            }
            replacement = GroupMessaging(
                lane=group.lane,
                policy=group.policy,
                communication=group.communication,
                providers=group.providers,
                config_digest=group.config_digest,
                egress=current,
                controlled_readers=True,
                loaded_store_bindings=group._loaded_store_bindings,
            )
            return boot(
                replace(
                    previous,
                    egress=current,
                    service=replace(
                        previous.service,
                        receiving=replace(
                            previous.service.receiving, channels={"tribe": replacement}
                        ),
                        messaging=replace(
                            previous.service.messaging,
                            channels={"tribe": replacement},
                            deliveries={"tribe": replacement},
                        ),
                    ),
                ),
                publication=publication,
            )

        second = successor(first)
        start(second)
        self.assertTrue(second.egress.reader_ready("tribe", reader()))
        self.assertEqual(
            second.egress.reader_recovery_status("tribe")["state"], "recovered"
        )
        with self.assertRaisesRegex(NativeEgressError, "reader_process_conflict"):
            select(second.egress, value, "e" * 64)
        changed = successor(second, publication="9" * 64)
        start(changed)
        self.assertFalse(changed.egress.reader_ready("tribe", reader()))
        self.assertEqual(
            group.records.reader_control_head("tribe")["action"], "invalidate"
        )

    def test_signed_application_composes_explicit_controlled_group(self):
        group_fixtures.GroupRuntimeTests.test_group_only_application_uses_supported_signed_provisioning(
            self
        )

    def test_loaded_publication_and_view_digest_survive_disk_pointer_and_record_changes(
        self,
    ):
        from daimon_matrix.messaging_config import (
            create_binding,
            load_application,
            read_document,
            read_verified_publication,
        )

        base, app, view = group_fixtures.GroupRuntimeTests._signed_group_application(
            self, record_key_check=False
        )
        loaded = json.loads(view.service.loaded_application)
        selected = read_verified_publication(base, app)
        digest = loaded["loaded_view_sha256"]
        group = view.service.messaging.channels["tribe"]
        gate = loaded["reader_gates"]["tribe"]
        self.assertEqual(gate["process_id"], os.getpid())
        self.assertEqual(gate["context_sha256"], loaded["config_sha256"])
        self.assertEqual(
            loaded["loaded_base_sha256"],
            hashlib.sha256(base.service.loaded_runtime).hexdigest(),
        )
        self.assertEqual(
            set(loaded["stores"]),
            {"records", "envelopes", "opaque-message", "opaque-evidence"},
        )
        self.assertNotIn(str(app), canonical_bytes(loaded).decode())
        group.records.reserve(
            "request",
            str(uuid.uuid4()),
            {"text": "ordinary committed row"},
            lambda: {"text": "ordinary committed row"},
        )
        current = load_application(base, app)
        self.assertEqual(
            json.loads(current.service.loaded_application)["loaded_view_sha256"], digest
        )
        packet = read_document(app / "publication.json")
        generation = "generation-" + uuid.uuid4().hex
        directory = app / generation
        directory.mkdir(mode=0o700)
        for name in ("application.json", "binding.json", "client.json"):
            shutil.copyfile(app / name, directory / name)
            (directory / name).chmod(0o600)
        body = {**packet["body"], "generation": generation}
        (app / "publication.json").write_bytes(
            canonical_bytes({"body": body, "binding": create_binding(base, body)})
        )
        self.assertEqual(
            json.loads(view.service.loaded_application)["publication"], packet["body"]
        )
        retained = load_application(base, app, verified_publication=selected)
        self.assertEqual(
            json.loads(retained.service.loaded_application)["loaded_view_sha256"],
            digest,
        )
        newer = load_application(base, app)
        self.assertEqual(
            json.loads(newer.service.loaded_application)["publication"], body
        )
        self.assertNotEqual(
            json.loads(newer.service.loaded_application)["loaded_view_sha256"], digest
        )

    def test_replaced_group_store_invalidates_view_before_any_request_journal_write(
        self,
    ):
        _base, _app, view = group_fixtures.GroupRuntimeTests._signed_group_application(
            self, record_key_check=False
        )
        group = view.service.messaging.channels["tribe"]
        path = group.records.path
        old = path.with_name("retained-records.sqlite")
        path.rename(old)
        shutil.copyfile(old, path)
        path.chmod(0o600)
        observer = next(
            cap
            for cap in view.service.capabilities.values()
            if "runtime.status" in cap.methods
        )
        request = create_request(
            observer,
            request_id=str(uuid.uuid4()),
            method="runtime.status",
            params={},
            issued_at_ms=view.service.clock(),
        )
        with patch.object(view.service.ledger, "begin_rpc") as begin:
            response = view.service.handle(request)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "loaded_store_replaced")
        begin.assert_not_called()
        with self.assertRaisesRegex(ServiceError, "loaded_store_replaced"):
            group.validate(view.service)
        from daimon_matrix.routes import RouteAmbiguous

        # HTTP intake and its deferred recovery bypass the owner RPC service.
        # A byte-identical replacement must stay uncertain before either can
        # inspect, commit or acknowledge storage under the old loaded view.
        context = {"request": {"request_id": str(uuid.uuid4())}}
        operations = (
            lambda: group.admit_message(context),
            lambda: group.admit_evidence(context),
            lambda: group.retained_message_ticket(context),
            lambda: group.retained_evidence_ticket(context),
            lambda: group._acknowledge_intake({}, context, b"{}"),
            lambda: group.complete_receipt(str(uuid.uuid4())),
            lambda: group.complete_control(str(uuid.uuid4())),
            lambda: group.reconcile_intake(),
            lambda: group.receive_message(b"{}"),
            lambda: group.receive_evidence(b"{}"),
        )
        with (
            patch.object(group.records, "get") as read,
            patch.object(group.records, "reserve") as write,
            patch.object(group.records, "commit_intake") as intake,
            patch.object(group.records, "commit_control") as control,
            patch.object(group.records, "intake_page") as page,
        ):
            for operation in operations:
                with self.assertRaisesRegex(
                    RouteAmbiguous, "tribe_loaded_store_uncertain"
                ):
                    operation()
            for store_access in (read, write, intake, control, page):
                store_access.assert_not_called()

    def test_loaded_group_authorities_include_verified_foreign_historical_epochs(self):
        old = self.fixture.member.authority
        current, _origin = group_fixtures.DirectLaneTests.enroll_second_member_body(
            self
        )
        self.fixture.member = replace(self.fixture.member, authority=current)
        _base, _app, view = group_fixtures.GroupRuntimeTests._signed_group_application(
            self, record_key_check=False
        )
        observed = json.loads(view.service.loaded_application)["authorities"]
        ref = current.manifest.being_ref
        self.assertEqual(
            observed[ref],
            {
                "active_manifest_hash": current.manifest.digest,
                "active_control_head": current.state.head,
                "accepted_manifest_hashes": sorted(
                    [old.manifest.digest, current.manifest.digest]
                ),
            },
        )
        self.assertEqual(
            set(observed),
            {self.fixture.founder.state.being_ref, self.fixture.member.state.being_ref},
        )
        # The boot observation cannot silently follow a later resolver change.
        loaded_group = view.service.messaging.channels["tribe"]
        loaded_group.lane.authority_resolver = lambda _ref: current
        self.assertEqual(
            json.loads(view.service.loaded_application)["authorities"], observed
        )

    def test_authenticated_invalid_intake_cannot_persist_into_replaced_opaque_store(
        self,
    ):
        import hmac

        from daimon_matrix.canonical import b64url
        from daimon_matrix.routes import RouteAmbiguous, RouteError

        _base, _app, view = group_fixtures.GroupRuntimeTests._signed_group_application(
            self, record_key_check=False
        )
        ingress = view.messaging_http.message_ingress
        path = ingress.inbox.path
        old = path.with_name("retained-opaque.sqlite")
        path.rename(old)
        shutil.copyfile(old, path)
        path.chmod(0o600)
        retained_bytes = path.read_bytes()
        now = ingress.clock()
        unsigned = {
            "schema": "dm.transport-request/v1",
            "version": "v1",
            "provider_ref": ingress.provider_ref,
            "route_ref": ingress.route_ref,
            "request_id": str(uuid.uuid4()),
            "issued_at_ms": now,
            "expires_at_ms": now + 60_000,
            "sender_principal": "synthetic-test-sender",
            "sender_body_ref": "synthetic-test-body",
            # Authenticated but semantically invalid: no intake callback runs.
            "submission": {},
        }
        auth = {
            "schema": "dm.transport-auth/v1",
            "alg": "HMAC-SHA256",
            "key_ref": ingress.key_ref,
            "value": b64url(
                hmac.digest(ingress._secret, canonical_bytes(unsigned), "sha256")
            ),
        }
        with patch.object(ingress.inbox, "admit_response") as refused:
            with self.assertRaisesRegex(RouteAmbiguous, "tribe_loaded_store_uncertain"):
                ingress.handle_deferred(canonical_bytes({**unsigned, "auth": auth}))
            refused.assert_not_called()
        self.assertEqual(path.read_bytes(), retained_bytes)
        # A request without authenticated route authorship cannot consult the
        # owner-local storage guard or reveal its state.
        with patch.object(ingress, "store_guard") as guarded:
            with self.assertRaisesRegex(RouteError, "transport_request_rejected"):
                ingress.handle_deferred(
                    canonical_bytes(
                        {**unsigned, "auth": {**auth, "value": b64url(b"x" * 32)}}
                    )
                )
            guarded.assert_not_called()


class ReaderSelectionTests(unittest.TestCase):
    def test_typed_validity_is_closed_and_refuses_future_or_expired_binding(self):
        c = self.controller
        select(c, command(c))
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        invalid = [
            {"mode": "until-revoked", "not_before_ms": True},
            {"mode": "until-revoked", "not_before_ms": 0, "not_after_ms": None},
            {"mode": "unknown", "not_before_ms": 0},
            {"mode": "finite", "not_before_ms": 0},
            {"mode": "finite", "not_before_ms": 0, "not_after_ms": self.now},
            {"mode": "until-revoked", "not_before_ms": self.now + 1},
        ]
        for validity in invalid:
            with self.subTest(validity=validity), self.assertRaises(NativeEgressError):
                select(
                    c,
                    command(c, phase="select", readers=[reader_v2(validity=validity)]),
                )
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)

    def setUp(self):
        self.now = 1_000
        self.controller = synthetic_visibility(clock=lambda: self.now)
        self.controller.register_reader_channel("tribe", "0" * 64)

    def test_default_denial_revoke_select_expiry_and_retained_exact_retry(self):
        c = self.controller
        row = reader()
        self.assertFalse(c.reader_ready("tribe", row))
        with self.assertRaisesRegex(NativeEgressError, "reader_revocation_required"):
            select(c, command(c, phase="select", readers=[row]))
        revoked = select(c, command(c))
        value = command(c, phase="select", readers=[row])
        request = "e" * 64
        selected = select(c, value, request)
        self.assertTrue(c.reader_ready("tribe", row))
        self.assertNotEqual(selected["head"], revoked["head"])
        self.now = row["expires_at_ms"]
        self.assertFalse(c.reader_ready("tribe", row))
        self.assertEqual(select(c, value, request), selected)

    def test_revocation_of_empty_rows_advances_head_and_rejects_delayed_enable(self):
        c = self.controller
        first = select(c, command(c))
        delayed = command(c, phase="select", readers=[reader()])
        second = select(c, command(c))
        self.assertEqual(second["readers"], [])
        self.assertNotEqual(second["head"], first["head"])
        with self.assertRaisesRegex(NativeEgressError, "reader_selection_conflict"):
            select(c, delayed)
        self.assertFalse(c.reader_ready("tribe", reader()))

    def test_revoked_operation_cannot_be_taken_over_before_its_selected_commit(self):
        c = self.controller
        select(c, command(c))
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        for phase in ("revoke", "select"):
            with (
                self.subTest(phase=phase),
                self.assertRaisesRegex(NativeEgressError, "reader_operation_conflict"),
            ):
                select(c, command(c, phase=phase, operation_id=str(uuid.uuid4())))
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)
        select(c, command(c, phase="select"))
        # A selected empty projection completes the reservation without granting
        # any reader. The next controlled update can reserve a new operation.
        next_operation = str(uuid.uuid4())
        self.assertEqual(
            select(c, command(c, operation_id=next_operation))["operation_id"],
            next_operation,
        )

    def test_snapshot_and_input_mutations_cannot_change_live_readers(self):
        c = self.controller
        select(c, command(c))
        row = reader()
        selected = select(c, command(c, phase="select", readers=[row]))
        row["credential_id"] = "wrong"
        selected["readers"][0]["credential_id"] = "also-wrong"
        selected["readers"][0]["authority_epochs"].clear()
        selected["readers"][0]["wire_read"].clear()
        self.assertTrue(c.reader_ready("tribe", reader()))
        self.assertTrue(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("b" * 64,),
            )
        )
        self.assertFalse(c.reader_ready("tribe", reader(credential_id="wrong")))

    def test_superseded_request_and_restarted_process_cannot_restore_enable(self):
        c = self.controller
        select(c, command(c))
        value = command(c, phase="select", readers=[reader()])
        request = "e" * 64
        select(c, value, request)
        select(c, command(c))
        with self.assertRaisesRegex(NativeEgressError, "reader_selection_conflict"):
            select(c, value, request)
        restarted = synthetic_visibility(clock=lambda: self.now)
        restarted.register_reader_channel("tribe", "0" * 64)
        with self.assertRaisesRegex(NativeEgressError, "reader_process_conflict"):
            select(restarted, value, request)
        self.assertFalse(restarted.reader_ready("tribe", reader()))

    def test_closed_bounded_rows_and_unknown_channels_fail_without_transition(self):
        c = self.controller
        select(c, command(c))
        value = command(c, phase="select", readers=[reader()])
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        variants = [
            {**value, "extra": True},
            {**value, "channel_id": []},
            {**value, "channel_id": "unknown"},
            {**value, "readers": [reader(), reader()]},
            {**value, "readers": [reader(expires_at_ms=True)]},
            {**value, "readers": [reader(expires_at_ms=self.now)]},
            {**value, "readers": [reader(extra=True)]},
        ]
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(NativeEgressError):
                select(c, changed)
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)

    def test_warm_reconstruction_cannot_rebind_a_loaded_context(self):
        c = self.controller
        select(c, command(c))
        select(c, command(c, phase="select", readers=[reader()]))
        before = c.reader_snapshot("tribe", deadline_ns=budget())
        c.register_reader_channel("tribe", "0" * 64)
        self.assertEqual(c.reader_snapshot("tribe", deadline_ns=budget()), before)
        with self.assertRaisesRegex(NativeEgressError, "reader_context_conflict"):
            c.register_reader_channel("tribe", "1" * 64)

    def test_same_credentials_do_not_authorize_uncovered_wire_or_authority_epoch(self):
        c = self.controller
        select(c, command(c))
        select(c, command(c, phase="select", readers=[reader()]))
        self.assertFalse(
            c.reader_ready("tribe", reader(), required_wire="unsupported/v9")
        )
        self.assertFalse(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("f" * 64,),
            )
        )
        self.assertTrue(
            c.reader_ready(
                "tribe",
                reader(),
                required_wire="dm.tribe.direct-conversation/v1",
                required_authority_epochs=("b" * 64,),
            )
        )


class DurableReaderRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 1_000

        def sign(value):
            return hmac.digest(
                b"synthetic-record-key", canonical_bytes(value), "sha256"
            ).hex()

        def verify(value, binding):
            if not hmac.compare_digest(sign(value), binding):
                raise ValueError("synthetic_binding_invalid")

        self.records = TribeRecordStore(
            Path(self.directory.name) / "records.db",
            sign=sign,
            verify=verify,
            clock=lambda: self.now,
            cache_reader_bindings=True,
        )
        self.binding = {
            key: "unchanged"
            for key in (
                "code",
                "sdk",
                "authority",
                "credential",
                "stores",
                "publication",
                "visibility",
            )
        }
        self.roster = "b" * 64

    def restart(self, *, binding=None, deadline_ns=None):
        controller = synthetic_visibility(clock=lambda: self.now)
        controller.register_reader_channel("tribe", "0" * 64, controlled=True)

        def authorized(expected, *, readers=None):
            if expected != self.roster:
                raise ValueError("reader_roster_conflict")
            return nullcontext()

        controller.initialize_reader_recovery(
            "tribe",
            binding=self.binding if binding is None else binding,
            boot={"process": controller._reader_instance_id},
            load=self.records.reader_control_head,
            append=self.records.append_reader_control,
            authorization=authorized,
            **({"deadline_ns": deadline_ns} if deadline_ns is not None else {}),
        )
        return controller

    def test_custom_verifier_does_not_cache_by_default(self):
        self.enabled_v2()
        self.records.cache_reader_bindings = False
        with patch.object(self.records, "verify", wraps=self.records.verify) as verify:
            self.records.reader_control_head("tribe")
            before = verify.call_count
            self.records.reader_control_head("tribe")
            self.assertGreater(before, 0)
            self.assertEqual(verify.call_count, before * 2)

    def test_warm_reader_control_does_not_reverify_unchanged_signed_history(self):
        current, _ = self.enabled_v2()
        verify = self.records.verify
        monotonic = [1_000_000_000]
        checked = []

        def slow_verify(value, binding):
            monotonic[0] += 1_200_000_000
            checked.append(value["record_id"])
            verify(value, binding)

        self.records.verify = slow_verify
        with patch("time.monotonic_ns", lambda: monotonic[0]):
            self.records.reader_control_head("tribe")
            self.assertGreaterEqual(len(checked), 2)
            before = len(checked)
            current.select_readers(
                command(current),
                request_sha256="f" * 64,
                deadline_ns=monotonic[0] + 2_000_000_000,
            )
        self.assertEqual(len(checked), before)
        self.assertEqual(
            current.reader_snapshot("tribe", deadline_ns=budget())["phase"], "revoke"
        )

    def test_warm_reader_history_keeps_canonicalization_inside_control_budget(self):
        self.enabled_v2()
        self.records.reader_control_head("tribe")
        monotonic = [1_000_000_000]
        large_passes = []

        def costly_canonical(value):
            # Boot/context grows with real retained authority history. Charge
            # each full pass, independently of machine speed or a timing sleep.
            if isinstance(value, dict) and ("boot" in value or "document" in value):
                monotonic[0] += 600_000_000
                large_passes.append(value)
            return canonical_bytes(value)

        with patch("time.monotonic_ns", lambda: monotonic[0]), patch(
            "daimon_matrix.messaging_store.canonical_bytes", costly_canonical
        ):
            head = self.records.reader_control_head(
                "tribe", deadline_ns=monotonic[0] + 2_000_000_000
            )
            self.records._reader_budget(3_000_000_000)
        self.assertEqual(head["command"]["phase"], "select")
        self.assertEqual(len(large_passes), head["revision"])

    def test_warm_reader_hash_reuse_rejects_changed_document_and_signed_fork(self):
        self.enabled_v2()
        self.records.reader_control_head("tribe")
        with closing(sqlite3.connect(self.records.path)) as database:
            database.row_factory = sqlite3.Row
            original = dict(database.execute(
                "SELECT * FROM tribe_records WHERE kind='reader-control' "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone())
        for resign in (False, True):
            with self.subTest(resign=resign):
                changed = json.loads(bytes(original["document"]))
                changed["predecessor_sha256"] = "f" * 64
                raw = canonical_bytes(changed)
                binding = original["binding"]
                if resign:
                    signed = {key: original[key] for key in (
                        "kind", "record_id", "request_hash", "recorded_at_ms"
                    )}
                    binding = canonical_bytes(self.records.sign({
                        **signed, "document": changed
                    }))
                with closing(sqlite3.connect(self.records.path)) as database, database:
                    database.execute(
                        "UPDATE tribe_records SET document=?,document_hash=?,binding=? "
                        "WHERE sequence=?",
                        (raw, hashlib.sha256(raw).hexdigest(), binding,
                         original["sequence"]),
                    )
                expected = (
                    "reader_journal_chain_invalid" if resign
                    else "synthetic_binding_invalid"
                )
                with self.assertRaisesRegex(ValueError, expected):
                    self.records.reader_control_head("tribe")
                with closing(sqlite3.connect(self.records.path)) as database, database:
                    database.execute(
                        "UPDATE tribe_records SET document=?,document_hash=?,binding=? "
                        "WHERE sequence=?",
                        (original["document"], original["document_hash"],
                         original["binding"], original["sequence"]),
                    )
                self.records.reader_control_head("tribe")

    def test_reader_signature_cache_rejects_changed_signed_fields_and_binding(self):
        self.enabled_v2()
        self.records.reader_control_head("tribe")
        with closing(sqlite3.connect(self.records.path)) as database:
            database.row_factory = sqlite3.Row
            original = dict(
                database.execute(
                    "SELECT * FROM tribe_records WHERE kind='reader-control' "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
            )
        changes = {
            "record_id": str(uuid.uuid4()),
            "request_hash": "0" * 64,
            "recorded_at_ms": original["recorded_at_ms"] + 1,
            "binding": canonical_bytes("invalid-synthetic-binding"),
        }
        for key, value in changes.items():
            with self.subTest(field=key):
                with closing(sqlite3.connect(self.records.path)) as database, database:
                    database.execute(
                        "UPDATE tribe_records SET " + key + "=? WHERE sequence=?",
                        (value, original["sequence"]),
                    )
                with self.assertRaisesRegex(ValueError, "synthetic_binding_invalid"):
                    self.records.reader_control_head("tribe")
                with closing(sqlite3.connect(self.records.path)) as database, database:
                    database.execute(
                        "UPDATE tribe_records SET " + key + "=? WHERE sequence=?",
                        (original[key], original["sequence"]),
                    )
                self.records.reader_control_head("tribe")

    def test_valid_startup_can_authenticate_both_scans_beyond_two_seconds(self):
        self.enabled_v2()
        verify = self.records.verify
        monotonic = [1_000_000_000]

        def slow_verify(value, binding):
            monotonic[0] += 1_500_000_000
            verify(value, binding)

        self.records.verify = slow_verify
        with patch("time.monotonic_ns", lambda: monotonic[0]):
            current = self.restart()
        self.assertGreater(monotonic[0], 3_000_000_000)
        self.assertEqual(current.reader_recovery_status("tribe")["state"], "recovered")
        self.assertTrue(current.reader_ready("tribe", reader_v2()))

    def test_one_expired_startup_deadline_preserves_positive_intent_and_safe_cause(
        self,
    ):
        self.enabled_v2()
        before = self.records.reader_control_head("tribe")
        verify = self.records.verify
        monotonic = [1_000_000_000]

        def slow_verify(value, binding):
            monotonic[0] += 1_500_000_000
            verify(value, binding)

        self.records.verify = slow_verify
        with (
            patch("time.monotonic_ns", lambda: monotonic[0]),
            self.assertRaisesRegex(
                NativeEgressError, "reader_recovery_startup_uncertain"
            ) as raised,
        ):
            self.restart(deadline_ns=3_000_000_000)
        self.assertEqual(
            raised.exception.recovery_failure,
            {"stage": "load", "code": "reader_journal_deadline_expired"},
        )
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(self.records.reader_control_head("tribe"), before)

    def test_late_committed_rebound_is_preserved_without_successful_recovery(self):
        self.enabled_v2()
        before = self.records.reader_control_head("tribe")
        append = self.records.append_reader_control
        monotonic = [1_000_000_000]

        def late_append(*args, **kwargs):
            result = append(*args, **kwargs)
            monotonic[0] = 3_000_000_000
            return result

        self.records.append_reader_control = late_append
        with (
            patch("time.monotonic_ns", lambda: monotonic[0]),
            self.assertRaisesRegex(
                NativeEgressError, "reader_recovery_startup_uncertain"
            ) as raised,
        ):
            self.restart(deadline_ns=3_000_000_000)
        after = self.records.reader_control_head("tribe")
        self.assertEqual(after["action"], "rebound")
        self.assertEqual(after["command"], before["command"])
        self.assertNotEqual(after, before)
        self.assertEqual(
            raised.exception.recovery_failure,
            {"stage": "append", "code": "reader_journal_deadline_expired"},
        )

    def test_runtime_without_receivers_cannot_publish_ready_after_deadline(self):
        from daimon_matrix import daemon

        root = Path(self.directory.name)
        info = root.stat()
        monotonic = [1_000_000_000]

        def slow_registry(_paths):
            monotonic[0] = 3_000_000_000

        runtime = SimpleNamespace(
            state_root=root,
            state_identity=(info.st_dev, info.st_ino),
            socket_path=root / "test.sock",
            service=SimpleNamespace(receiving=None),
            egress=SimpleNamespace(validate_registry=slow_registry),
        )
        reader_fd, writer_fd = os.pipe()
        try:
            with (
                patch("time.monotonic_ns", lambda: monotonic[0]),
                patch.object(daemon, "_enabled_egress_paths", return_value=[]),
                self.assertRaisesRegex(
                    daemon.DaemonError, "reader_journal_deadline_expired"
                ),
            ):
                daemon.serve_forever(
                    runtime,
                    ready_descriptor=writer_fd,
                    startup_deadline_ns=3_000_000_000,
                )
            self.assertFalse(runtime.socket_path.exists())
            os.set_blocking(reader_fd, False)
            with self.assertRaises(BlockingIOError):
                os.read(reader_fd, 16)
        finally:
            os.close(reader_fd)
            os.close(writer_fd)

    def enabled(self):
        controller = self.restart()
        select(controller, command(controller))
        value = command(controller, phase="select", readers=[reader()])
        controller.select_readers(
            value,
            request_sha256="e" * 64,
            deadline_ns=budget(),
            recovery_roster_sha256=self.roster,
        )
        return controller, value

    def enabled_v2(self, *, finite=False):
        controller = self.restart()
        select(controller, command(controller))
        row = reader_v2()
        if finite:
            row["validity"] = {
                "mode": "finite",
                "not_before_ms": 0,
                "not_after_ms": 20_000,
            }
        value = command(controller, phase="select", readers=[row])
        controller.select_readers(
            value,
            request_sha256="e" * 64,
            deadline_ns=budget(),
            recovery_roster_sha256=self.roster,
        )
        return controller, value

    def test_typed_binding_passes_old_proof_horizon_and_recovers_mixed_history(self):
        old, value = self.enabled_v2()
        head = self.records.reader_control_head("tribe")
        self.assertEqual(head["schema"], "dm.receiving.reader-control-record/v2")
        self.now = 20_001
        self.assertTrue(old.reader_ready("tribe", value["readers"][0]))
        current = self.restart()
        self.assertTrue(current.reader_ready("tribe", value["readers"][0]))
        self.assertEqual(current.reader_recovery_status("tribe")["state"], "recovered")
        self.assertIsNone(current.reader_recovery_status("tribe")["eligible_until_ms"])
        self.assertEqual(
            self.records.reader_control_head("tribe")["schema"], head["schema"]
        )

    def test_real_finite_typed_expiry_still_invalidates_recovery(self):
        old, value = self.enabled_v2(finite=True)
        self.now = 20_000
        self.assertFalse(old.reader_ready("tribe", value["readers"][0]))
        self.assertEqual(old.reader_recovery_status("tribe")["state"], "expired")
        current = self.restart()
        self.assertFalse(current.reader_ready("tribe", value["readers"][0]))
        self.assertEqual(
            self.records.reader_control_head("tribe")["action"], "invalidate"
        )

    def test_restart_restores_fixed_vector_and_new_provenance_without_old_request(self):
        old, request = self.enabled()
        prior = old.reader_snapshot("tribe", deadline_ns=budget())
        current = self.restart()
        gate = current.reader_snapshot("tribe", deadline_ns=budget())
        self.assertEqual(gate["readers"], prior["readers"])
        self.assertEqual(gate["phase"], "select")
        self.assertNotEqual(gate["process_instance_id"], prior["process_instance_id"])
        self.assertNotEqual(gate["head"], prior["head"])
        self.assertIsNone(gate["request_sha256"])
        self.assertEqual(current.reader_recovery_status("tribe")["state"], "recovered")
        with self.assertRaisesRegex(NativeEgressError, "reader_process_conflict"):
            select(current, request, "e" * 64)
        self.assertEqual(self.records.reader_control_head("tribe")["action"], "rebound")

    def test_latest_revoke_and_empty_select_survive_restart_and_warm_composition(self):
        current, _ = self.enabled()
        select(current, command(current))
        # The same startup initializer cannot re-enable a later live revoke.
        current.initialize_reader_recovery(
            "tribe",
            binding=self.binding,
            boot={},
            load=self.records.reader_control_head,
            append=self.records.append_reader_control,
            authorization=lambda _: nullcontext(),
        )
        self.assertFalse(current.reader_ready("tribe", reader()))
        self.assertFalse(self.restart().reader_ready("tribe", reader()))
        select(current, command(current, phase="select"))
        self.assertFalse(self.restart().reader_ready("tribe", reader()))

    def test_incompatible_or_expired_latest_selection_is_consumed_not_resurrected(self):
        for changed in (*self.binding, "roster", "expiry"):
            with self.subTest(changed=changed):
                self.records = TribeRecordStore(
                    Path(self.directory.name) / (changed + ".db")
                )
                self.now, self.roster = 1_000, "b" * 64
                self.enabled()
                binding = dict(self.binding)
                if changed == "roster":
                    self.roster = "c" * 64
                elif changed == "expiry":
                    self.now = 20_000
                else:
                    binding[changed] = "changed"
                self.assertFalse(
                    self.restart(binding=binding).reader_ready("tribe", reader())
                )
                self.assertEqual(
                    self.records.reader_control_head("tribe")["action"], "invalidate"
                )
                self.now, self.roster = 1_000, "b" * 64
                self.assertFalse(self.restart().reader_ready("tribe", reader()))

    def test_signed_order_ignores_sql_sequence_and_rejects_document_tampering(self):
        self.enabled()
        with closing(sqlite3.connect(self.records.path)) as database, database:
            database.execute(
                "UPDATE tribe_records SET sequence=sequence+100 "
                "WHERE kind='reader-control'"
            )
        self.assertTrue(self.restart().reader_ready("tribe", reader()))
        with closing(sqlite3.connect(self.records.path)) as database, database:
            database.execute(
                "UPDATE tribe_records SET document=? "
                "WHERE kind='reader-control' "
                "AND sequence=(SELECT MAX(sequence) FROM tribe_records)",
                (b"{}",),
            )
        with self.assertRaisesRegex(
            NativeEgressError, "reader_recovery_startup_uncertain"
        ):
            self.restart()

    def test_failed_persistence_disables_and_exact_retry_is_one_record(
        self,
    ):
        current, value = self.enabled()
        before = self.records.reader_control_head("tribe")
        select(current, value, "e" * 64)
        self.assertEqual(self.records.reader_control_head("tribe"), before)
        state = current._reader_recovery["tribe"]

        def failed(*_, **__):
            raise OSError("synthetic_io_failure")

        state["append"] = failed
        with self.assertRaisesRegex(
            NativeEgressError, "reader_recovery_persistence_uncertain"
        ):
            select(current, command(current))
        self.assertFalse(current.reader_ready("tribe", reader()))
        self.assertEqual(
            current.reader_recovery_status("tribe")["state"], "persistence-uncertain"
        )

    def test_new_operation_retries_before_commit_or_reconciles_lost_commit_result(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                self.records = TribeRecordStore(
                    Path(self.directory.name) / (str(committed) + ".db")
                )
                current, _ = self.enabled()
                value = command(current, operation_id=str(uuid.uuid4()))
                state = current._reader_recovery["tribe"]
                append = state["append"]

                def interrupted(*args, committed=committed, append=append, **kwargs):
                    if committed:
                        append(*args, **kwargs)
                    raise OSError("synthetic_lost_commit")

                state["append"] = interrupted
                if committed:
                    result = select(current, value, "f" * 64)
                    self.assertEqual(result["operation_id"], value["operation_id"])
                else:
                    with self.assertRaisesRegex(
                        NativeEgressError, "reader_recovery_persistence_uncertain"
                    ):
                        select(current, value, "f" * 64)
                self.assertFalse(current.reader_ready("tribe", reader()))
                state["append"] = append
                result = select(current, value, "f" * 64)
                self.assertEqual(result["operation_id"], value["operation_id"])
                self.assertEqual(
                    self.records.reader_control_head("tribe")["revision"], 3
                )

    def test_transient_startup_io_preserves_intent_but_failed_tombstone_refuses_boot(
        self,
    ):
        self.enabled()
        before = self.records.reader_control_head("tribe")

        def failed(*_, **__):
            raise OSError("synthetic_io_failure")

        current = synthetic_visibility(clock=lambda: self.now)
        current.register_reader_channel("tribe", "0" * 64, controlled=True)
        with self.assertRaisesRegex(
            NativeEgressError, "reader_recovery_startup_uncertain"
        ):
            current.initialize_reader_recovery(
                "tribe",
                binding=self.binding,
                boot={},
                load=failed,
                append=self.records.append_reader_control,
                authorization=lambda _: nullcontext(),
            )
        self.assertFalse(current.reader_ready("tribe", reader()))
        self.assertEqual(self.records.reader_control_head("tribe"), before)
        self.assertTrue(self.restart().reader_ready("tribe", reader()))
        changed = synthetic_visibility(clock=lambda: self.now)
        changed.register_reader_channel("tribe", "0" * 64, controlled=True)
        with self.assertRaisesRegex(
            NativeEgressError, "reader_recovery_invalidation_uncertain"
        ):
            changed.initialize_reader_recovery(
                "tribe",
                binding={"different": True},
                boot={},
                load=self.records.reader_control_head,
                append=failed,
                authorization=lambda _: nullcontext(),
            )
        self.assertFalse(changed.reader_ready("tribe", reader()))

    def test_contended_store_does_not_extend_the_native_control_deadline(self):
        current, _ = self.enabled()
        with closing(sqlite3.connect(self.records.path)) as other:
            other.execute("BEGIN IMMEDIATE")
            start = time.monotonic()
            with self.assertRaisesRegex(
                NativeEgressError, "reader_recovery_persistence_uncertain"
            ):
                select(current, command(current, operation_id=str(uuid.uuid4())))
            self.assertLess(time.monotonic() - start, 1)
        self.assertFalse(current.reader_ready("tribe", reader()))


class ReaderHTTPTests(unittest.TestCase):
    def setUp(self):
        self.fixture = group_fixtures.GroupRuntimeTests()
        self.fixture.controlled_readers = getattr(self, "controlled_readers", False)
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def arguments(self, sender, receiver):
        value = self.fixture.direct_arguments(sender, receiver)
        if getattr(self, "controlled_readers", False):
            value.pop("destination")
        return value

    def test_root_advance_with_same_recipient_key_stays_unattempted(self):
        from tests.test_group_messaging_runtime import DirectLaneTests

        f = self.fixture
        sender, receiver = f.groups
        c = sender.egress
        select(c, command(c))
        row = reader(
            being_ref=receiver.lane.being_ref,
            embodiment_id=receiver.lane.local_embodiment_id,
            credential_id=receiver.lane.local_credential_id,
            incarnation_id=receiver.ledger.local_origin["incarnation_id"],
            authority_manifest_hash=receiver.ledger.authority.manifest.digest,
            expires_at_ms=receiver.lane.clock() + 60_000,
            authority_epochs=sorted(
                {
                    receiver.ledger.authority.manifest.digest,
                    sender.ledger.authority.manifest.digest,
                    *(
                        event["manifest_hash"]
                        for event in sender.lane.relationships.events()
                    ),
                }
            ),
        )
        select(c, command(c, phase="select", readers=[row]))
        helper = DirectLaneTests()
        helper.fixture = f.fixture
        current, _ = helper.enroll_second_member_body()
        self.assertNotIn(current.manifest.digest, row["authority_epochs"])
        # The existing body retains its key and transport, but the new carrier
        # requires an epoch not proved in the selected loaded-view observation.
        result = f.send_and_settle(sender, **f.direct_arguments(sender, receiver))
        self.assertEqual(len(result["audience"]), 2)
        existing = next(
            item
            for item in result["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(existing["current_route"], "available")
        self.assertEqual(existing["attempt_state"], "not-attempted")
        self.assertFalse(existing["reader_readiness"])
        self.assertEqual(receiver.page(after=0, limit=10), [])

    def test_revoke_waits_for_actual_http_write_and_blocks_subsequent_direct(self):
        f = self.fixture
        sender, receiver = f.groups
        c = sender.egress
        select(c, command(c))
        select(
            c,
            command(
                c,
                phase="select",
                readers=[
                    reader(
                        being_ref=receiver.lane.being_ref,
                        embodiment_id=receiver.lane.local_embodiment_id,
                        credential_id=receiver.lane.local_credential_id,
                        incarnation_id=receiver.ledger.local_origin["incarnation_id"],
                        authority_manifest_hash=receiver.ledger.authority.manifest.digest,
                        expires_at_ms=receiver.lane.clock() + 60_000,
                        authority_epochs=sorted(
                            {
                                receiver.ledger.authority.manifest.digest,
                                sender.ledger.authority.manifest.digest,
                                *(
                                    event["manifest_hash"]
                                    for event in sender.lane.relationships.events()
                                ),
                            }
                        ),
                    )
                ],
            ),
        )
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        original = provider._round_trip
        entered, released, revoking, revoked = (threading.Event() for _ in range(4))
        failures, outcomes = [], []

        def open_exchange(deadline):
            exchange = original.bounded_open(deadline)

            def physical_write(raw):
                entered.set()
                if not released.wait(5):
                    raise AssertionError("physical writer release missing")
                exchange.write(raw)

            return replace(exchange, write=physical_write)

        def send():
            try:
                outcomes.append(sender.send(**self.arguments(sender, receiver)))
            except BaseException as failure:
                failures.append(failure)

        value = command(c)

        def revoke():
            try:
                revoking.set()
                select(c, value)
                revoked.set()
            except BaseException as failure:
                failures.append(failure)

        provider._round_trip = replace(original, bounded_open=open_exchange)
        sending = threading.Thread(target=send)
        revocation = threading.Thread(target=revoke)
        try:
            sending.start()
            self.assertTrue(entered.wait(5))
            revocation.start()
            self.assertTrue(revoking.wait(5))
            self.assertFalse(revoked.wait(0.05))
        finally:
            released.set()
            sending.join(10)
            if revocation.ident is not None:
                revocation.join(10)
            provider._round_trip = original
        self.assertFalse(sending.is_alive())
        self.assertFalse(revocation.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(revoked.is_set())
        for server in [*f.servers, f.servers[0]]:
            server._threads.join()
        previous = sender.inspect(client_id="test", send_id=outcomes[0]["send_id"])
        self.assertTrue(previous["semantic"]["terminal"])
        native = copy.deepcopy(sender.records.get("native", outcomes[0]["send_id"]))
        previous_remote = next(
            item
            for item in previous["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(previous_remote["attempt_state"], "recipient-intake")
        self.assertFalse(previous_remote["reader_readiness"])
        denied = f.send_and_settle(sender, **self.arguments(sender, receiver))
        remote = next(
            item
            for item in denied["transport"]
            if item["embodiment_id"] == receiver.lane.local_embodiment_id
        )
        self.assertEqual(remote["attempt_state"], "not-attempted")
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(
            canonical_bytes(sender.records.get("native", outcomes[0]["send_id"])),
            canonical_bytes(native),
        )


class ControlledGroupTests(unittest.TestCase):
    controlled_readers = True
    setUp = ReaderHTTPTests.setUp
    arguments = ReaderHTTPTests.arguments

    def test_changed_stored_membership_epoch_refuses_before_provider_preparation(self):
        import sqlite3
        from contextlib import ExitStack, closing

        f = self.fixture
        sender, receiver = f.groups
        arguments = self.arguments(sender, receiver)
        initial = f.send_and_settle(sender, **arguments)
        plan = sender.records.get("send", initial["send_id"])
        proof = plan["sender_proof"]
        event = next(
            event
            for event in sender.lane.relationships.events()
            if event["event_id"] == proof["membership_event_id"]
        )
        corrupted = {**event, "manifest_hash": "f" * 64}
        self.assertEqual(corrupted["content_hash"], event["content_hash"])
        with (
            closing(sqlite3.connect(sender.lane.relationships.path)) as database,
            database,
        ):
            updated = database.execute(
                "UPDATE events SET event_json=? WHERE event_id=?",
                (canonical_bytes(corrupted), event["event_id"]),
            )
            self.assertEqual(updated.rowcount, 1)
        self.assertIn(corrupted, sender.lane.relationships.events())
        with ExitStack() as stack:
            preparations = [
                stack.enter_context(
                    patch.object(provider["message"], "prepare_submission")
                )
                for provider in sender.providers.values()
            ]
            with self.assertRaises(ValueError):
                sender.send(**arguments)
            for preparation in preparations:
                preparation.assert_not_called()

    def test_revoke_waits_for_actual_group_write(self):
        ReaderHTTPTests.test_revoke_waits_for_actual_http_write_and_blocks_subsequent_direct(
            self
        )

    def install_baseline(self):
        sender, receiver = self.fixture.groups
        select(sender.egress, command(sender.egress))
        value = reader(
            being_ref=receiver.lane.being_ref,
            embodiment_id=receiver.lane.local_embodiment_id,
            credential_id=receiver.lane.local_credential_id,
            incarnation_id=receiver.ledger.local_origin["incarnation_id"],
            authority_manifest_hash=receiver.ledger.authority.manifest.digest,
            expires_at_ms=receiver.lane.clock() + 60_000,
            authority_epochs=sorted(
                {
                    receiver.ledger.authority.manifest.digest,
                    sender.ledger.authority.manifest.digest,
                    *(
                        event["manifest_hash"]
                        for event in sender.lane.relationships.events()
                    ),
                }
            ),
        )
        select(sender.egress, command(sender.egress, phase="select", readers=[value]))
        return value

    def remote(self, result):
        receiver = self.fixture.groups[1]
        return next(
            row
            for row in result["transport"]
            if row["embodiment_id"] == receiver.lane.local_embodiment_id
        )

    def test_unselected_group_and_direct_retain_audiences_then_exact_group_retry(self):
        f = self.fixture
        sender, receiver = f.groups
        arguments = self.arguments(sender, receiver)
        first = f.send_and_settle(sender, **arguments)
        self.assertEqual(first["schema"], "dm.tribe.delivery/v1")
        self.assertEqual(len(first["audience"]), 2)
        self.assertEqual(self.remote(first)["attempt_state"], "not-attempted")
        direct = f.send_and_settle(sender, **f.direct_arguments(sender, receiver))
        self.assertEqual(len(direct["audience"]), 1)
        self.assertEqual(self.remote(direct)["attempt_state"], "not-attempted")
        retained = sender.records.get("native", first["send_id"])
        self.install_baseline()
        second = f.send_and_settle(sender, **arguments)
        self.assertTrue(second["semantic"]["terminal"])
        self.assertEqual(second["message_id"], first["message_id"])
        self.assertEqual(second["audience"], first["audience"])
        self.assertEqual(sender.records.get("native", first["send_id"]), retained)
        self.assertEqual(len(receiver.page(after=0, limit=10)), 1)
        self.assertEqual(
            receiver.egress.reader_snapshot("tribe", deadline_ns=budget())["phase"],
            "unselected",
        )
        # Signed return dispatch and the author's control intake need no positive
        # data projection. Their actual authority/visibility fences still run.
        self.assertEqual(self.remote(second)["attempt_state"], "recipient-intake")

    def test_controlled_group_rejects_opaque_and_unbounded_transport(self):
        from unittest.mock import Mock

        f = self.fixture
        sender, receiver = f.groups
        self.install_baseline()
        provider = sender.providers[
            (receiver.lane.being_ref, receiver.lane.local_embodiment_id)
        ]["message"]
        original = provider._round_trip
        for value in (Mock(), replace(original, bounded_open=None)):
            with self.subTest(opaque=type(value).__name__):
                provider._round_trip = value
                result = f.send_and_settle(sender, **self.arguments(sender, receiver))
                self.assertEqual(self.remote(result)["attempt_state"], "unconfirmed")
                self.assertEqual(receiver.page(after=0, limit=10), [])
                if isinstance(value, Mock):
                    value.assert_not_called()
        provider._round_trip = original

    def test_expired_selection_and_callback_override_cannot_restore_legacy_mode(self):
        f = self.fixture
        sender, receiver = f.groups
        value = self.install_baseline()
        f.fixture.now = value["expires_at_ms"]
        sender.direct_reader_ready = lambda row: True
        result = f.send_and_settle(sender, **self.arguments(sender, receiver))
        self.assertEqual(self.remote(result)["attempt_state"], "not-attempted")
        self.assertEqual(receiver.page(after=0, limit=10), [])
        self.assertTrue(sender.controlled_readers)
        with self.assertRaisesRegex(NativeEgressError, "reader_context_conflict"):
            sender.egress.register_reader_channel("tribe", sender.config_digest)

    def test_group_reader_does_not_cover_new_epoch_with_unchanged_key(self):
        f = self.fixture
        sender, receiver = f.groups
        value = self.install_baseline()
        helper = group_fixtures.DirectLaneTests()
        helper.fixture = f.fixture
        current, _ = helper.enroll_second_member_body()
        self.assertNotIn(current.manifest.digest, value["authority_epochs"])
        result = f.send_and_settle(sender, **self.arguments(sender, receiver))
        self.assertEqual(len(result["audience"]), 3)
        self.assertEqual(self.remote(result)["attempt_state"], "not-attempted")
        self.assertEqual(receiver.page(after=0, limit=10), [])
