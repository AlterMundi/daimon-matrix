"""A freshly activated body must be hostable with --closed-visibility (#187).

`daimon-rebirth activate` produces a clean package and the documented way to host a
body that has no Telegram mirror of its own is `daimon-matrixd --closed-visibility`.
That combination could not start: the two catalogs the peer transport registers hold
only their peer tables, `validate_registry` demands the echo subset exactly, and every
caller of the installer requires a messaging application or a link ceremony that this
body by definition does not have. The daemon then reported one opaque line.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

from daimon_matrix import daemon
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.daemon import _enabled_egress_paths, _safe_detail
from daimon_matrix.mandatory_echo import EchoError, EchoJournal
from daimon_matrix.messaging_config import config_digest, create_binding
from daimon_matrix.native_egress import (
    NativeEgressError,
    closed_visibility,
)
from daimon_matrix.peer_transport import (
    SCOPE_REQUEST,
    SCOPE_RESPONSE,
    PeerTransportError,
)
from daimon_matrix.runtime import load_runtime
from tests.test_dm024_runtime import NOW, PASSWORD, RuntimeFixture
from tests.test_mandatory_echo_integration import SignedVisibilityInstallationTests
from tests.test_messaging_runtime import seed

VISIBILITY_TABLES = {
    "mandatory_egress_operations",
    "echo_v2_catalog",
    "echo_v2_obligations",
}


def _tables(path: Path) -> set[str]:
    database = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {
            row[0]
            for row in database.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            )
        }
    finally:
        database.close()


@contextlib.contextmanager
def diagnostics() -> Iterator[io.BytesIO]:
    """Capture the daemon's binary diagnostic stream.

    `_log` writes canonical JSON to `sys.stderr.buffer`, so a text-only redirect
    cannot see it and would fail on the missing attribute instead of the behaviour
    under test.
    """

    raw = io.BytesIO()

    class _Stderr:
        buffer = raw

        def write(self, text: str) -> int:
            return raw.write(text.encode("utf-8"))

        def flush(self) -> None:
            return None

    previous = sys.stderr
    sys.stderr = _Stderr()  # type: ignore[assignment]
    try:
        yield raw
    finally:
        sys.stderr = previous


class ClosedVisibilityProvisioningTests(RuntimeFixture):
    def body(self, name: str = "hosted") -> tuple[Path, Any]:
        """One body with peer transport and no messaging application at all."""

        root, bundle, _capability = self.make_bundle(
            secrets={"peer.encryption.v1:local": seed("legion-encryption")},
            state_name=name,
        )
        bundle["peer_transport"] = {
            "enabled": True,
            "encryption_slot": "peer.encryption.v1:local",
            "exchange_filename": "peer-exchange.sqlite",
            "outbox_filename": "peer-outbox.sqlite",
            "listen_host": "127.0.0.1",
            "listen_port": 45193,
            # The bundle's targets must be exactly the other active embodiments of
            # this being, so a body with peer transport is never target-less here.
            "targets": [
                {
                    "embodiment_id": "embodiment:daimonmatrix",
                    "endpoint": "http://127.0.0.1:45194/dm-peer/v1",
                    "timeout_ms": 1000,
                }
            ],
        }
        (root / "runtime.json").write_bytes(canonical_bytes(bundle))

        def clock() -> int:
            return NOW

        runtime = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=clock,
            egress=closed_visibility(clock=clock, catalog_mode="migrate"),
        )
        return root, runtime

    def provision(self, root: Path) -> int:
        """Run the documented verb for real, password through a descriptor.

        The daemon reads the wall clock, while the fixture's credentials are valid
        in a window around its own synthetic NOW, so the daemon's clock is pinned to
        the fixture's. That is the seam under test's own input, not a stub of the
        behaviour being checked.
        """

        password_file = root.parent / f"{root.name}.password"
        password_file.write_bytes(PASSWORD)
        password_file.chmod(0o600)
        descriptor = os.open(password_file, os.O_RDONLY)
        with (
            diagnostics() as stderr,
            patch.object(daemon.time, "time_ns", return_value=NOW * 1_000_000),
        ):
            code = daemon.main(
                [
                    "--state-root",
                    str(root),
                    "--closed-visibility",
                    "--provision-visibility",
                    "--password-fd",
                    str(descriptor),
                ]
            )
        self.assertIn(b"visibility_provisioned", stderr.getvalue())
        return code

    def installation(self, root: Path, runtime: Any) -> Path:
        fixture = SignedVisibilityInstallationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        document = fixture._sibling_document()
        document["runtime_id"] = runtime.service.runtime_id
        document["application_sha256"] = config_digest(
            json.loads((root / "runtime.json").read_bytes())
        )
        being = runtime.service.ledger.authority.manifest.being_ref
        disclosure = document["disclosure"]
        disclosure["participants"] = [being]
        for channel in disclosure["scope"]["channels"]:
            channel["local_being_ref"] = being
            channel["peer_being_ref"] = being
        disclosure["scope_sha256"] = config_digest(disclosure["scope"])
        acceptance = document["acceptance_set"]
        acceptance["disclosure_sha256"] = config_digest(disclosure)
        acceptance["bindings"] = [create_binding(runtime, disclosure)]
        document["policy"]["acceptance_digest"] = config_digest(acceptance)
        path = fixture.root / "visibility.json"
        path.write_bytes(
            canonical_bytes(
                {"document": document, "binding": create_binding(runtime, document)}
            )
        )
        path.chmod(0o600)
        return path

    def adopt(self, root: Path, installation: Path) -> tuple[int, bytes]:
        password_file = root.parent / f"{root.name}.adopt-password"
        password_file.write_bytes(PASSWORD)
        password_file.chmod(0o600)
        descriptor = os.open(password_file, os.O_RDONLY)
        with (
            diagnostics() as stderr,
            patch.object(daemon.time, "time_ns", return_value=NOW * 1_000_000),
            patch.object(
                daemon, "serve_forever", side_effect=AssertionError("must not serve")
            ),
        ):
            code = daemon.main(
                [
                    "--state-root",
                    str(root),
                    "--visibility-installation",
                    str(installation),
                    "--adopt-owner-visibility",
                    "--password-fd",
                    str(descriptor),
                ]
            )
        return code, stderr.getvalue()

    def test_owner_adoption_preserves_real_native_history_and_is_idempotent(
        self,
    ) -> None:
        root, runtime = self.body("owner-adoption")
        self.assertEqual(self.provision(root), 0)
        context = runtime.peer_context
        assert context is not None
        endpoint = context.endpoints["embodiment:daimonmatrix"][0]

        def refuse(_request: bytes) -> bytes:
            raise PeerTransportError()

        client = context.client("embodiment:daimonmatrix", endpoint, refuse)
        request_id = "05500000-0000-4000-8000-000000000055"
        with self.assertRaises(PeerTransportError):
            client.call(
                {
                    "schema": "dm.scope.request/v1",
                    "request_id": request_id,
                    "scope": "/we",
                },
                recipient_target=context.target("embodiment:daimonmatrix"),
                request_content_type=SCOPE_REQUEST,
                response_content_type=SCOPE_RESPONSE,
                correlation_id=request_id,
                deadline_ms=NOW + 30000,
            )

        def snapshot() -> dict[str, Any]:
            result = {}
            for name in ("peer-outbox.sqlite", "peer-exchange.sqlite"):
                with contextlib.closing(sqlite3.connect(root / name)) as database:
                    native = {
                        table: database.execute(
                            "SELECT * FROM " + table + " ORDER BY 1"
                        ).fetchall()
                        for table in sorted(_tables(root / name) - VISIBILITY_TABLES)
                    }
                    records = []
                    for (raw,) in database.execute(
                        "SELECT record FROM echo_v2_obligations ORDER BY operation_id"
                    ):
                        record = json.loads(raw)
                        record.pop("authentication")
                        records.append(record)
                    result[name] = {
                        "native": native,
                        "operations": database.execute(
                            "SELECT * FROM mandatory_egress_operations "
                            "ORDER BY operation_id"
                        ).fetchall(),
                        "proofs": records,
                    }
            return result

        before = snapshot()
        self.assertEqual(len(before["peer-outbox.sqlite"]["operations"]), 1)
        installation = self.installation(root, runtime)
        code, diagnostic = self.adopt(root, installation)
        self.assertEqual(code, 0, diagnostic)
        self.assertIn(b"owner_visibility_adopted", diagnostic)
        self.assertEqual(snapshot(), before)
        self.assertEqual(self.adopt(root, installation)[0], 0)
        self.assertEqual(snapshot(), before)
        restarted = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
            egress_factory=daemon._visibility_factory(installation, clock=lambda: NOW),
        )
        restarted.egress.validate_registry(_enabled_egress_paths(restarted))
        self.assertTrue(restarted.egress.mirror_sibling_conversations)

    def test_owner_adoption_resumes_after_one_catalog_commits(self) -> None:
        root, runtime = self.body("resumed-owner-adoption")
        self.assertEqual(self.provision(root), 0)
        installation = self.installation(root, runtime)
        original = EchoJournal.reauthenticate
        calls = 0

        def interrupted(journal: EchoJournal, key: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise EchoError("echo_storage_unavailable")
            original(journal, key)

        with patch.object(EchoJournal, "reauthenticate", interrupted):
            self.assertEqual(self.adopt(root, installation)[0], 1)
        self.assertEqual(calls, 2)
        self.assertEqual(self.adopt(root, installation)[0], 0)
        restarted = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
            egress_factory=daemon._visibility_factory(installation, clock=lambda: NOW),
        )
        restarted.egress.validate_registry(_enabled_egress_paths(restarted))

    def test_owner_adoption_preflights_all_catalogs_and_refuses_bad_binding(
        self,
    ) -> None:
        root, runtime = self.body("bad-owner-adoption")
        self.assertEqual(self.provision(root), 0)
        installation = self.installation(root, runtime)
        with contextlib.closing(
            sqlite3.connect(root / "peer-outbox.sqlite")
        ) as database:
            database.execute("DROP TABLE echo_v2_obligations")
            database.commit()
        before = (root / "peer-exchange.sqlite").read_bytes()
        self.assertEqual(self.adopt(root, installation)[0], 1)
        self.assertEqual((root / "peer-exchange.sqlite").read_bytes(), before)
        envelope = json.loads(installation.read_bytes())
        envelope["binding"]["signature"] = "A" * 86
        installation.write_bytes(canonical_bytes(envelope))
        self.assertEqual(self.adopt(root, installation)[0], 1)
        self.assertEqual((root / "peer-exchange.sqlite").read_bytes(), before)

    def test_a_fresh_body_cannot_serve_until_it_is_provisioned(self) -> None:
        root, runtime = self.body("unprovisioned")
        # The reported defect, reproduced: the daemon's own pre-bind check refuses.
        with self.assertRaises(NativeEgressError):
            runtime.egress.validate_registry(_enabled_egress_paths(runtime))
        for name in ("peer-outbox.sqlite", "peer-exchange.sqlite"):
            self.assertFalse(
                _tables(root / name) & VISIBILITY_TABLES,
                f"{name} already had the echo subset",
            )

        self.assertEqual(self.provision(root), 0)

        # Same runtime object, same registry, now valid: nothing but the catalog
        # databases changed.
        runtime.egress.validate_registry(_enabled_egress_paths(runtime))
        for name in ("peer-outbox.sqlite", "peer-exchange.sqlite"):
            tables = _tables(root / name)
            self.assertTrue(tables >= VISIBILITY_TABLES, name)
            self.assertEqual(
                {t for t in tables if t.startswith(("mandatory_egress_", "echo_v2_"))},
                VISIBILITY_TABLES,
                f"{name} carries exactly the echo subset and nothing else",
            )
        # The peer transport's own tables are untouched by provisioning.
        self.assertIn("peer_outbox", _tables(root / "peer-outbox.sqlite"))
        self.assertIn("peer_exchanges", _tables(root / "peer-exchange.sqlite"))

    def test_provisioning_is_idempotent_and_never_enables_release(self) -> None:
        root, runtime = self.body("idempotent")
        self.assertEqual(self.provision(root), 0)
        before = {
            name: (root / name).read_bytes()
            for name in ("peer-outbox.sqlite", "peer-exchange.sqlite")
        }
        self.assertEqual(self.provision(root), 0)
        after = {
            name: _tables(root / name)
            for name in ("peer-outbox.sqlite", "peer-exchange.sqlite")
        }
        self.assertEqual(
            after,
            {name: _tables(root / name) for name in before},
            "a second run adds no schema",
        )
        # A closed body has no transport and provisioning must not give it one:
        # this is the difference between receive-only and a body that can post.
        self.assertFalse(runtime.egress.release_enabled)
        self.assertEqual(runtime.egress.catalog_mode, "migrate")
        # And no messaging application appeared as a side effect.
        self.assertEqual(
            [p.name for p in root.iterdir() if "application" in p.name], []
        )

    def test_a_genuinely_invalid_catalog_still_fails_closed(self) -> None:
        root, _runtime = self.body("invalid")
        self.assertEqual(self.provision(root), 0)
        # Drop one required table: provisioning must refuse, not silently rebuild.
        database = sqlite3.connect(root / "peer-outbox.sqlite")
        try:
            database.execute("DROP TABLE echo_v2_obligations")
            database.commit()
        finally:
            database.close()
        password_file = root.parent / "invalid.password"
        password_file.write_bytes(PASSWORD)
        password_file.chmod(0o600)
        descriptor = os.open(password_file, os.O_RDONLY)
        with (
            diagnostics() as stderr,
            patch.object(daemon.time, "time_ns", return_value=NOW * 1_000_000),
        ):
            code = daemon.main(
                [
                    "--state-root",
                    str(root),
                    "--closed-visibility",
                    "--provision-visibility",
                    "--password-fd",
                    str(descriptor),
                ]
            )
        self.assertEqual(code, 1)
        emitted = stderr.getvalue()
        self.assertIn(b"startup_refused", emitted)
        # The cause is named, which is the whole point: one opaque line for every
        # possible failure is what turned a schema gap into an investigation.
        self.assertIn(b"egress_catalog_invalid", emitted)
        # And naming it carries nothing else out of the process.
        for fragment in (str(root).encode(), b"password", b"custody.json"):
            self.assertNotIn(fragment, emitted)

    def test_the_verb_refuses_combinations_that_would_duplicate_another_path(
        self,
    ) -> None:
        root, _runtime = self.body("guards")
        installation = root.parent / "installation.json"
        installation.write_bytes(b"{}")
        installation.chmod(0o600)
        for argv, expected in (
            (
                [
                    "--state-root",
                    str(root),
                    "--closed-visibility",
                    "--adopt-owner-visibility",
                    "--password-fd",
                    "3",
                ],
                "owner_visibility_adoption_never_serves",
            ),
            (
                [
                    "--state-root",
                    str(root),
                    "--visibility-installation",
                    str(installation),
                    "--adopt-owner-visibility",
                    "--ready-fd",
                    "4",
                    "--password-fd",
                    "3",
                ],
                "owner_visibility_adoption_never_serves",
            ),
            (
                [
                    "--state-root",
                    str(root),
                    "--visibility-installation",
                    str(installation),
                    "--provision-visibility",
                    "--password-fd",
                    "3",
                ],
                "provision_visibility_requires_closed_visibility",
            ),
            (
                [
                    "--state-root",
                    str(root),
                    "--closed-visibility",
                    "--provision-visibility",
                    "--ready-fd",
                    "4",
                    "--password-fd",
                    "3",
                ],
                "provision_visibility_never_serves",
            ),
        ):
            with diagnostics() as stderr:
                code = daemon.main(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn(expected.encode(), stderr.getvalue())


class StartupDiagnosticTests(unittest.TestCase):
    def test_a_project_code_is_reported_and_a_path_is_not(self) -> None:
        self.assertEqual(
            _safe_detail(NativeEgressError("egress_catalog_invalid")),
            "NativeEgressError:egress_catalog_invalid",
        )
        self.assertEqual(
            _safe_detail(daemon.DaemonError("state_root_not_owner_only")),
            "DaemonError:state_root_not_owner_only",
        )

    def test_anything_that_is_not_a_bare_code_is_withheld(self) -> None:
        for exception in (
            OSError(2, "No such file", "/home/owner/.local/state/body/custody.json"),
            KeyError("/home/owner/.config/daimon-matrix/body.password"),
            ValueError("password is hunter2 and the key is AAEC"),
            RuntimeError("http://10.0.0.7:8686/dm-peer/v1 refused"),
            NativeEgressError("egress_catalog_invalid /etc/secret"),
        ):
            detail = _safe_detail(exception)
            self.assertEqual(detail, type(exception).__name__, detail)
            for fragment in (
                "/home",
                "/etc",
                "hunter2",
                "AAEC",
                "10.0.0.7",
                "custody",
                "password",
                " ",
            ):
                self.assertNotIn(fragment, detail)

    def test_the_type_name_is_always_present(self) -> None:
        class Custom(Exception):
            pass

        self.assertEqual(_safe_detail(Custom("x y z")), "Custom")
        self.assertTrue(_safe_detail(Custom()).startswith("Custom"))


if __name__ == "__main__":
    unittest.main()
