"""Owner-local upgrade tests: only freshly generated unrelated legacy custody."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from daimon_matrix import operator_runtime_upgrade as upgrade
from daimon_matrix.keystore import EncryptedKeystore

LEGACY: Path  # Assigned lazily by setUpClass; never download during collection.
PASSWORD = b"synthetic-upgrade-password"


def acquire_legacy(parent: Path) -> Path:
    """Mandatory pinned fixture: offline DM_LEGACY_SOURCE, local git, then HTTPS.

    No source code executes before the complete production pin verifies. One
    bounded public download at most; missing prerequisites FAIL rather than skip.
    """
    import io
    import tarfile
    import urllib.request

    explicit = os.environ.get("DM_LEGACY_SOURCE")
    try:
        if explicit is not None:
            path = Path(explicit)
        else:
            repo = Path(__file__).resolve().parents[1]
            archive = subprocess.run(
                ["git", "-C", str(repo), "archive", upgrade.LEGACY_REVISION, "src"],
                capture_output=True,
                timeout=30,
            )
            if archive.returncode == 0:
                raw = archive.stdout
                prefix = "src/"
            else:
                url = (
                    "https://codeload.github.com/AlterMundi/daimon-matrix/tar.gz/"
                    + upgrade.LEGACY_REVISION
                )
                with urllib.request.urlopen(url, timeout=60) as response:
                    raw = response.read(32 * 1024 * 1024 + 1)
                prefix = "daimon-matrix-" + upgrade.LEGACY_REVISION + "/src/"
            if len(raw) > 32 * 1024 * 1024:
                raise AssertionError("legacy archive exceeds fixture limit")
            contents = {}
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tar:
                total = 0
                for item in tar:
                    if not item.name.startswith(prefix) or item.isdir():
                        continue
                    name = item.name[len(prefix) :]
                    if (
                        not item.isfile()
                        or not name
                        or Path(name).is_absolute()
                        or ".." in Path(name).parts
                    ):
                        raise AssertionError("unsafe legacy archive member")
                    total += item.size
                    if total > 32 * 1024 * 1024 or name in contents:
                        raise AssertionError("invalid legacy archive inventory")
                    stream = tar.extractfile(item)
                    assert stream is not None
                    contents[name] = stream.read()
            if upgrade._inventory(contents) != upgrade.LEGACY_SOURCE_SHA256:
                raise AssertionError("legacy fixture artifact hash mismatch")
            path = parent / "pinned-legacy-src"
            upgrade._copy(contents, path)
        if (
            upgrade._inventory(upgrade._snapshot(path, private=False))
            != upgrade.LEGACY_SOURCE_SHA256
        ):
            raise AssertionError("legacy fixture artifact hash mismatch")
        return path
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        raise AssertionError(
            "legacy fixture unavailable/invalid; preseed DM_LEGACY_SOURCE "
            "with the pinned src tree"
        ) from error


def files(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


class LegacyAcquisitionTests(unittest.TestCase):
    def test_acquire_pinned_artifact_without_scratch_path(self):
        import io
        import tarfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seeded = acquire_legacy(root)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as tar:
                tar.add(seeded, arcname="src")
            (root / "local").mkdir(mode=0o700)
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, buffer.getvalue(), b""
                    ),
                ),
            ):
                path = acquire_legacy(root / "local")
            self.assertEqual(
                upgrade._inventory(upgrade._snapshot(path, private=False)),
                upgrade.LEGACY_SOURCE_SHA256,
            )

    def test_public_download_when_git_object_unavailable(self):
        import io
        import tarfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            seeded = acquire_legacy(root)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                tar.add(
                    seeded, arcname="daimon-matrix-" + upgrade.LEGACY_REVISION + "/src"
                )
            (root / "download").mkdir(mode=0o700)
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 1, b"", b""),
                ),
                patch(
                    "urllib.request.urlopen", return_value=io.BytesIO(buffer.getvalue())
                ) as download,
            ):
                path = acquire_legacy(root / "download")
            download.assert_called_once()
            self.assertEqual(
                upgrade._inventory(upgrade._snapshot(path, private=False)),
                upgrade.LEGACY_SOURCE_SHA256,
            )

    def test_explicit_missing_or_wrong_artifact_is_failure(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            for path in (Path(temp) / "missing", Path(temp)):
                with (
                    patch.dict(os.environ, {"DM_LEGACY_SOURCE": str(path)}),
                    self.assertRaises(AssertionError),
                ):
                    acquire_legacy(Path(temp))


class RuntimeUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global LEGACY
        cls.fixture = tempfile.TemporaryDirectory(prefix="dm-upgrade-fixture-")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.base = Path(cls.fixture.name)
        LEGACY = acquire_legacy(cls.base)
        script = """
import sys, os, json, time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from daimon_matrix.operator_bootstrap import _create
from daimon_matrix.runtime import load_runtime

root = Path(sys.argv[2])
os.umask(0o077)
rows = [
    dict(
        label=x,
        body_ref="body:synthetic-" + x,
        principal_id="synthetic-" + x,
        listen_host="127.0.0.1",
        listen_port=47001 + i,
        advertised_endpoint=f"http://127.0.0.1:{47001 + i}/dm-peer/v1",
    )
    for i, x in enumerate(("alpha", "beta"))
]
p = root / "profile.json"
p.write_text(
    json.dumps(dict(schema="dm.operator.bootstrap-profile/v1", embodiments=rows))
)


def fd(secret=b"synthetic-upgrade-password"):
    r, w = os.pipe()
    os.write(w, secret)
    os.close(w)
    return r


_create(
    root / "ceremony",
    p,
    fd(b"synthetic-root-password"),
    [f"alpha={fd()}", f"beta={fd(b'synthetic-beta-password')}"],
)
r = root / "ceremony/runtimes/alpha"
rt = load_runtime(
    r,
    "runtime.json",
    lambda: bytearray(b"synthetic-upgrade-password"),
    clock=lambda: time.time_ns() // 1000000,
)
rt.service.ledger.append_local(
    kind="experience.observed",
    subject="synthetic:upgrade",
    payload={"text": "preserve this history"},
    signer=rt.service.signer,
    sensitivity="private",
    occurred_at_ms=time.time_ns() // 1000000,
)
(r / ".daimon-matrixd.lock").touch(mode=0o600)
"""
        subprocess.run(
            [sys.executable, "-I", "-B", "-c", script, str(LEGACY), str(cls.base)],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        import shutil

        self.temp = tempfile.TemporaryDirectory(prefix="dm-upgrade-test-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.source = self.parent / "runtime"
        shutil.copytree(self.base / "ceremony/runtimes/alpha", self.source)
        self.transaction = self.parent / "upgrade"
        self.bundle = json.loads((self.source / "runtime.json").read_bytes())
        self.before = files(self.source)
        self.now = time.time_ns() // 1000000

    def stage(self, **changes):
        args: dict[str, Any] = dict(
            source=self.source,
            transaction=self.transaction,
            legacy_source=LEGACY,
            legacy_sha256=upgrade.LEGACY_SOURCE_SHA256,
            expected_source_sha256=upgrade.inventory_digest(self.source),
            expected_counter=self.bundle["keystore"]["counter"],
            expected_control_head=self.bundle["control_head"],
            expected_being_ref=self.bundle["manifest"]["being_ref"],
            expected_origin=self.bundle["local_origin"],
            password=PASSWORD,
            expires_at_ms=self.now + 3600000,
            externally_quiesced=True,
        )
        args.update(changes)
        return upgrade.stage(**args)

    def provision_legacy_status(self, status_label="clusterd"):
        """Fresh fixture rotation via pinned legacy APIs, not a production repair."""
        script = """
import sys, os, json, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from daimon_matrix.operator_bootstrap import _private_write
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.local_api import create_capability
from daimon_matrix.runtime import load_runtime
root, label = Path(sys.argv[2]), sys.argv[3]
password = b"synthetic-upgrade-password"
bundle = json.loads((root / "runtime.json").read_bytes())
store = EncryptedKeystore(root / "custody.json")
current = store.open(lambda: bytearray(password))
old = next(row for row in bundle["capabilities"] if ":status:" in row["secret_slot"])
now = time.time_ns() // 1000000
cap = create_capability(
    os.urandom(32), client_id="client:status:" + label,
    methods=old["descriptor"]["methods"],
    not_before_ms=now, not_after_ms=now + 3600000,
)
slot = "runtime.capability.v1:status:" + label
secrets = {
    key: value for key, value in current.secrets.items() if key != old["secret_slot"]
}
secrets[slot] = cap.key
updated = store.rotate(
    lambda: bytearray(password), lambda: bytearray(password),
    expected_counter=current.counter, control_head=current.control_head,
    secrets=secrets,
)
bundle["capabilities"] = [row for row in bundle["capabilities"] if row != old] + [
    dict(descriptor=cap.descriptor, secret_slot=slot)
]
bundle["keystore"]["counter"] = updated.counter
(root / "runtime.json").unlink()
_private_write(root / "runtime.json", bundle)
load_runtime(
    root, "runtime.json", lambda: bytearray(password),
    clock=lambda: time.time_ns() // 1000000,
)
"""
        subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                script,
                str(LEGACY),
                str(self.source),
                status_label,
            ],
            check=True,
        )
        self.bundle = json.loads((self.source / "runtime.json").read_bytes())
        self.before = files(self.source)
        self.assertEqual(self.bundle["keystore"]["counter"], 2)

    def test_native_status_labels_preserve_exact_slots_through_forward_and_rollback(
        self,
    ):
        for status_label in ("alpha", "clusterd"):
            with self.subTest(status_label=status_label):
                self.setUp()
                self.provision_legacy_status(status_label)
                old = EncryptedKeystore(self.source / "custody.json").open(
                    lambda: bytearray(PASSWORD)
                )
                old_slots = {row["secret_slot"] for row in self.bundle["capabilities"]}
                self.assertEqual(
                    old_slots,
                    {
                        "runtime.capability.v1:alpha",
                        "runtime.capability.v1:status:" + status_label,
                    },
                )
                ready = self.stage()
                self.assertEqual(
                    (ready["counter_before"], ready["counter_after"]), (2, 3)
                )
                self.assertEqual(files(self.source), self.before)
                self.assertEqual(files(self.transaction / "checkpoint"), self.before)
                upgrade.publish(**self.publish_args())
                current = json.loads((self.source / "runtime.json").read_bytes())
                self.assertEqual(current["runtime_label"], "alpha")
                self.assertEqual(
                    current["runtime_id"],
                    upgrade.profiles.operator_runtime_id(
                        "alpha",
                        self.bundle["manifest"]["being_ref"],
                        self.bundle["local_origin"],
                        upgrade.signing_descriptor(
                            old.secrets["runtime.signing.v1:alpha"]
                        )["key_id"],
                    ),
                )
                custody = EncryptedKeystore(self.source / "custody.json").open(
                    lambda: bytearray(PASSWORD)
                )
                self.assertEqual(custody.counter, 3)
                self.assertFalse(old_slots & custody.secrets.keys())
                for slot in old.secrets.keys() - old_slots:
                    self.assertEqual(custody.secrets[slot], old.secrets[slot])
                reverse = upgrade.stage_rollback(**self.publish_args())
                self.assertEqual(
                    (reverse["counter_before"], reverse["counter_after"]), (3, 4)
                )
                upgrade.publish_rollback(**self.rollback_args())
                upgrade._validate(self.source, LEGACY, PASSWORD)
                restored = json.loads((self.source / "runtime.json").read_bytes())
                self.assertEqual(restored["capabilities"], self.bundle["capabilities"])
                custody = EncryptedKeystore(self.source / "custody.json").open(
                    lambda: bytearray(PASSWORD)
                )
                self.assertEqual(custody.counter, 4)
                self.assertEqual(custody.secrets, old.secrets)
                self.assertEqual(files(self.transaction / "checkpoint"), self.before)
                for name, digest in self.before.items():
                    if name not in {
                        "custody.json",
                        ".custody.json.highwater",
                        "runtime.json",
                    }:
                        self.assertEqual(files(self.source)[name], digest)

    def test_status_shape_refusals_preserve_source_before_transaction(self):
        for case in (
            "duplicate-status",
            "duplicate-operator",
            "empty-status",
            "missing-status",
            "missing-operator",
            "wrong-operator-label",
            "wrong-role",
            "extra-method",
            "duplicate-method",
            "malformed-slot",
            "malformed-descriptor",
            "overlapping-operator-status",
            "duplicate-overlapping-slot",
        ):
            with self.subTest(case=case):
                self.setUp()
                self.provision_legacy_status()
                rows = self.bundle["capabilities"]
                operator, status = rows
                if case == "duplicate-status":
                    rows[0] = status
                elif case == "duplicate-operator":
                    rows[1] = operator
                elif case == "empty-status":
                    status["secret_slot"] = "runtime.capability.v1:status:"
                elif case == "missing-status":
                    rows.pop()
                elif case == "missing-operator":
                    rows.pop(0)
                elif case == "wrong-operator-label":
                    operator["secret_slot"] = "runtime.capability.v1:other"
                elif case == "wrong-role":
                    status["descriptor"]["methods"] = ["runtime.status"]
                elif case == "extra-method":
                    status["descriptor"]["methods"].append("memory.append")
                elif case == "duplicate-method":
                    status["descriptor"]["methods"].append("runtime.status")
                elif case == "malformed-slot":
                    status["secret_slot"] = None
                elif case in {
                    "overlapping-operator-status",
                    "duplicate-overlapping-slot",
                }:
                    self.bundle["keystore"]["signing_slot"] = (
                        "runtime.signing.v1:status:clusterd"
                    )
                    operator["secret_slot"] = (
                        "runtime.capability.v1:unrelated"
                        if case == "overlapping-operator-status"
                        else status["secret_slot"]
                    )
                else:
                    status["descriptor"] = None
                (self.source / "runtime.json").write_bytes(
                    upgrade.canonical_bytes(self.bundle)
                )
                before = files(self.source)
                with self.assertRaises((upgrade.UpgradeError, TypeError, KeyError)):
                    self.stage()
                self.assertEqual(files(self.source), before)
                self.assertFalse(self.transaction.exists())

    def test_monotonic_rollback_restores_real_legacy_contract(self):
        self.stage()
        args = self.publish_args()
        upgrade.publish(**args)
        current = json.loads((self.source / "runtime.json").read_bytes())
        checkpoint = files(self.transaction / "checkpoint")
        ready = upgrade.stage_rollback(**args)
        self.assertEqual(ready["counter_before"], 2)
        self.assertEqual(ready["counter_after"], 3)
        candidate = self.transaction / "rollback"
        restored = json.loads((candidate / "runtime.json").read_bytes())
        for key in ("manifest", "local_origin", "control_head"):
            self.assertEqual(restored[key], current[key])
        self.assertEqual(restored["capabilities"], self.bundle["capabilities"])
        self.assertEqual(files(self.transaction / "checkpoint"), checkpoint)
        rollback_args = dict(
            args,
            expected_receipt_sha256=hashlib.sha256(
                (self.transaction / "rollback-ready.json").read_bytes()
            ).hexdigest(),
        )
        result = upgrade.publish_rollback(**rollback_args)
        upgrade._validate(self.source, LEGACY, PASSWORD)
        custody = EncryptedKeystore(self.source / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        self.assertEqual(custody.counter, 3)
        old = EncryptedKeystore(self.transaction / "validation" / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        self.assertEqual(custody.secrets, old.secrets)
        after = files(self.source)
        self.assertEqual(upgrade.publish_rollback(**rollback_args), result)
        self.assertEqual(upgrade.stage_rollback(**args), ready)
        self.assertEqual(files(self.source), after)
        self.assertEqual(files(self.transaction / "checkpoint"), checkpoint)
        for name in self.before:
            if name not in {"custody.json", ".custody.json.highwater", "runtime.json"}:
                self.assertEqual(after[name], self.before[name])

    def test_rollback_expired_legacy_authority_refuses_without_source_changes(self):
        from unittest.mock import patch

        self.stage()
        args = self.publish_args()
        upgrade.publish(**args)
        expiry = min(
            row["descriptor"]["not_after_ms"] for row in self.bundle["capabilities"]
        )
        before = files(self.source)
        with (
            patch.object(upgrade.time, "time_ns", return_value=(expiry + 1) * 1000000),
            self.assertRaisesRegex(
                upgrade.UpgradeError, "legacy_authorization_expired"
            ),
        ):
            upgrade.stage_rollback(**args)
        self.assertEqual(files(self.source), before)
        self.assertFalse((self.transaction / "rollback-ready.json").exists())

    def rollback_args(self):
        return dict(
            self.publish_args(),
            expected_receipt_sha256=hashlib.sha256(
                (self.transaction / "rollback-ready.json").read_bytes()
            ).hexdigest(),
        )

    def test_rollback_publication_rechecks_old_expiry(self):
        from unittest.mock import patch

        self.stage()
        args = self.publish_args()
        upgrade.publish(**args)
        upgrade.stage_rollback(**args)
        before = files(self.source)
        expiry = min(
            row["descriptor"]["not_after_ms"] for row in self.bundle["capabilities"]
        )
        with (
            patch.object(upgrade.time, "time_ns", return_value=(expiry + 1) * 1000000),
            self.assertRaisesRegex(
                upgrade.UpgradeError, "legacy_authorization_expired"
            ),
        ):
            upgrade.publish_rollback(**self.rollback_args())
        self.assertEqual(files(self.source), before)

    def test_reverse_reapproved_candidate_cannot_rewind_custody(self):
        self.stage()
        forward = self.publish_args()
        upgrade.publish(**forward)
        upgrade.stage_rollback(**forward)
        candidate = self.transaction / "rollback"
        for name in ("runtime.json", "custody.json", ".custody.json.highwater"):
            (candidate / name).write_bytes(
                (self.transaction / "checkpoint" / name).read_bytes()
            )
        ready_path = self.transaction / "rollback-ready.json"
        ready = json.loads(ready_path.read_bytes())
        ready["successor_sha256"] = upgrade.inventory_digest(candidate)
        ready_path.write_bytes(upgrade.canonical_bytes(ready))
        before = files(self.parent)
        with self.assertRaisesRegex(
            upgrade.UpgradeError, "candidate_contract_conflict"
        ):
            upgrade.publish_rollback(**self.rollback_args())
        self.assertEqual(files(self.parent), before)

    def test_rollback_cli_fd_and_approved_digest(self):
        self.stage()
        upgrade.publish(**self.publish_args())
        for command, receipt_name in (
            ("stage-rollback", "ready.json"),
            ("publish-rollback", "rollback-ready.json"),
        ):
            read, write = os.pipe()
            os.write(write, PASSWORD)
            os.close(write)
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "daimon_matrix.operator_runtime_upgrade",
                        command,
                        "--source",
                        str(self.source),
                        "--transaction",
                        str(self.transaction),
                        "--ready-sha256",
                        hashlib.sha256(
                            (self.transaction / receipt_name).read_bytes()
                        ).hexdigest(),
                        "--password-fd",
                        str(read),
                        "--externally-quiesced",
                    ],
                    pass_fds=(read,),
                    capture_output=True,
                )
            finally:
                os.close(read)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(PASSWORD, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["counter_after"], 3)
        upgrade._validate(self.source, LEGACY, PASSWORD)

    def test_reverse_exchange_interruptions_recover_exact_keys(self):
        from unittest.mock import patch

        for point in ("before", "after", "receipt"):
            with self.subTest(point=point):
                self.setUp()
                self.stage()
                forward = self.publish_args()
                upgrade.publish(**forward)
                ready = upgrade.stage_rollback(**forward)
                args = self.rollback_args()
                original_exchange, original_write = upgrade._exchange, upgrade._write

                def interrupted(
                    left, right, point=point, original_exchange=original_exchange
                ):
                    if point == "after":
                        original_exchange(left, right)
                    raise OSError("synthetic exchange interruption")

                def partial(path, data, original_write=original_write):
                    if path.name.startswith(".rolled-back-"):
                        original_write(path, data[:10])
                        raise OSError("synthetic receipt interruption")
                    original_write(path, data)

                target = "_write" if point == "receipt" else "_exchange"
                with (
                    patch.object(
                        upgrade,
                        target,
                        side_effect=partial if point == "receipt" else interrupted,
                    ),
                    self.assertRaises(OSError),
                ):
                    upgrade.publish_rollback(**args)
                result = upgrade.publish_rollback(**args)
                self.assertEqual(result["counter_after"], 3)
                self.assertEqual(
                    upgrade.inventory_digest(self.source), ready["successor_sha256"]
                )
                self.assertEqual(files(self.transaction / "checkpoint"), self.before)
                with patch.object(
                    EncryptedKeystore,
                    "rotate",
                    side_effect=AssertionError("no second rotation"),
                ):
                    self.assertEqual(upgrade.publish_rollback(**args), result)
                    self.assertEqual(upgrade.stage_rollback(**forward), ready)

    def test_reverse_mutations_refuse_preserving_all_evidence(self):
        for case in (
            "pre-stage-effect",
            "source",
            "candidate",
            "checkpoint",
            "old-source",
            "code",
            "ready",
            "forward",
        ):
            with self.subTest(case=case):
                self.setUp()
                self.stage()
                forward = self.publish_args()
                upgrade.publish(**forward)
                if case != "pre-stage-effect":
                    upgrade.stage_rollback(**forward)
                    args = self.rollback_args()
                root = {
                    "source": self.source,
                    "pre-stage-effect": self.source,
                    "candidate": self.transaction / "rollback",
                    "checkpoint": self.transaction / "checkpoint",
                    "old-source": self.transaction / "successor",
                    "code": self.transaction / "legacy-code",
                }.get(case)
                if root is not None:
                    path = root / (
                        "daimon_matrix/runtime.py"
                        if case == "code"
                        else "ledger.sqlite"
                    )
                else:
                    path = self.transaction / (
                        "ready.json" if case == "forward" else "rollback-ready.json"
                    )
                with path.open("ab") as stream:
                    stream.write(b"synthetic-effect")
                evidence = files(self.parent)
                with self.assertRaises((upgrade.UpgradeError, ValueError)):
                    if case == "pre-stage-effect":
                        upgrade.stage_rollback(**forward)
                    else:
                        upgrade.publish_rollback(**args)
                self.assertEqual(files(self.parent), evidence)

    def test_reverse_requires_quiescence_and_daemon_locks(self):
        import fcntl

        self.stage()
        forward = self.publish_args()
        upgrade.publish(**forward)
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.stage_rollback(**dict(forward, externally_quiesced=False))
        fd = os.open(self.source / upgrade.LOCK, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(OSError):
                upgrade.stage_rollback(**forward)
        finally:
            os.close(fd)
        upgrade.stage_rollback(**forward)
        args = self.rollback_args()
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.publish_rollback(**dict(args, externally_quiesced=False))
        fd = os.open(self.transaction / "rollback" / upgrade.LOCK, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(OSError):
                upgrade.stage_rollback(**forward)
            with self.assertRaises(OSError):
                upgrade.publish_rollback(**args)
        finally:
            os.close(fd)

    def test_exact_committed_retry_after_expiry_does_not_renew_keys(self):
        from unittest.mock import patch

        receipt = self.stage()
        args = self.publish_args()
        result = upgrade.publish(**args)
        with patch.object(
            upgrade.time,
            "time_ns",
            return_value=(receipt["expires_at_ms"] + 1) * 1000000,
        ):
            self.assertEqual(upgrade.publish(**args), result)
        self.assertEqual(
            upgrade.inventory_digest(self.source), receipt["successor_sha256"]
        )

    def test_non_bootstrap_legacy_shape_refuses_before_staging(self):
        self.bundle["keystore"]["filename"] = "other-custody.json"
        (self.source / "runtime.json").write_bytes(upgrade.canonical_bytes(self.bundle))
        with self.assertRaisesRegex(upgrade.UpgradeError, "unsupported_legacy_shape"):
            self.stage()
        self.assertFalse(self.transaction.exists())

    def test_preservation_covers_nonstandard_history_filenames(self):
        import sqlite3
        from unittest.mock import patch

        path = self.source / "history.db"
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE evidence(value TEXT)")
            connection.execute(
                "INSERT INTO evidence VALUES ('synthetic historical row')"
            )
        connection.close()
        path.chmod(0o600)
        before = files(self.source)
        original = upgrade._validate

        def changed(root, code, password):
            original(root, code, password)
            if root.name == "successor":
                with (root / "history.db").open("ab") as stream:
                    stream.write(b"changed")

        with (
            patch.object(upgrade, "_validate", side_effect=changed),
            self.assertRaisesRegex(upgrade.UpgradeError, "history_changed"),
        ):
            self.stage()
        self.assertEqual(files(self.source), before)
        self.assertFalse((self.transaction / "ready.json").exists())

    def publish_args(self) -> dict[str, Any]:
        return dict(
            source=self.source,
            transaction=self.transaction,
            expected_receipt_sha256=hashlib.sha256(
                (self.transaction / "ready.json").read_bytes()
            ).hexdigest(),
            password=PASSWORD,
            externally_quiesced=True,
        )

    def test_wrong_reviewed_inputs_refuse_before_staging(self):
        for change in (
            {"expected_source_sha256": "0" * 64},
            {"expected_counter": 99},
            {"expected_control_head": "wrong"},
            {"expected_being_ref": "wrong"},
            {"expected_origin": {}},
            {"legacy_sha256": "0" * 64},
            {"expires_at_ms": self.now - 1},
            {"externally_quiesced": False},
        ):
            with self.subTest(change=change):
                with self.assertRaises(upgrade.UpgradeError):
                    self.stage(**change)
                self.assertEqual(files(self.source), self.before)
                self.assertFalse(self.transaction.exists())

    def test_missing_tampered_and_duplicate_legacy_inputs_refuse(self):
        for case in (
            "missing-bundle",
            "ciphertext",
            "duplicate-row",
            "highwater",
            "wrong-password",
        ):
            with self.subTest(case=case):
                self.setUp()
                if case == "missing-bundle":
                    (self.source / "runtime.json").unlink()
                elif case == "ciphertext":
                    p = self.source / "custody.json"
                    value = json.loads(p.read_bytes())
                    value["ciphertext"] = (
                        "A" + value["ciphertext"][1:]
                        if value["ciphertext"][0] != "A"
                        else "B" + value["ciphertext"][1:]
                    )
                    p.write_bytes(upgrade.canonical_bytes(value))
                elif case == "duplicate-row":
                    self.bundle["capabilities"][1] = self.bundle["capabilities"][0]
                    (self.source / "runtime.json").write_bytes(
                        upgrade.canonical_bytes(self.bundle)
                    )
                elif case == "highwater":
                    (self.source / ".custody.json.highwater").write_text("99")
                before = files(self.source)
                with self.assertRaises((upgrade.UpgradeError, KeyError)):
                    self.stage(
                        **(
                            {"password": b"wrong-password"}
                            if case == "wrong-password"
                            else {}
                        )
                    )
                self.assertEqual(files(self.source), before)
                self.assertFalse((self.transaction / "ready.json").exists())

    def test_untrusted_legacy_artifact_is_never_executed(self):
        code = upgrade._snapshot(LEGACY, private=False)
        root = self.parent / "tampered-code"
        upgrade._copy(code, root)
        marker = self.parent / "executed"
        (root / "daimon_matrix/__init__.py").write_text(
            f'open({str(marker)!r}, "w").write("bad")'
        )
        with self.assertRaisesRegex(upgrade.UpgradeError, "artifact_mismatch"):
            self.stage(legacy_source=root)
        self.assertFalse(marker.exists())
        self.assertFalse(self.transaction.exists())
        self.assertEqual(files(self.source), self.before)

    def test_symlinks_hardlinks_special_files_modes_and_sqlite_sidecars_refuse(self):
        for case in (
            "symlink",
            "directory-symlink",
            "hardlink",
            "fifo",
            "mode",
            "-wal",
            "-shm",
            "-journal",
        ):
            with self.subTest(case=case):
                self.setUp()
                path = self.source / "unsafe"
                if case == "symlink":
                    path.symlink_to(self.source / "runtime.json")
                elif case == "directory-symlink":
                    path.symlink_to(self.parent, target_is_directory=True)
                elif case == "hardlink":
                    os.link(self.source / "runtime.json", path)
                elif case == "fifo":
                    os.mkfifo(path, 0o600)
                elif case == "mode":
                    (self.source / "runtime.json").chmod(0o644)
                else:
                    path = self.source / ("ledger.sqlite" + case)
                    path.touch(mode=0o600)
                with self.assertRaises((upgrade.UpgradeError, OSError)):
                    self.stage()
                self.assertFalse(self.transaction.exists())

    def test_runtime_lock_blocks_stage_without_source_changes(self):
        import fcntl

        fd = os.open(self.source / upgrade.LOCK, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(OSError):
                self.stage()
        finally:
            os.close(fd)
        self.assertEqual(files(self.source), self.before)
        self.assertFalse(self.transaction.exists())

    def test_publish_rejects_changed_source_checkpoint_candidate_and_receipt(self):
        for case in (
            "source",
            "checkpoint",
            "candidate",
            "receipt",
            "path-binding",
            "expiry",
        ):
            with self.subTest(case=case):
                self.setUp()
                self.stage()
                args = self.publish_args()
                if case == "receipt":
                    (self.transaction / "ready.json").write_text("{}")
                elif case == "path-binding":
                    args["transaction"] = self.parent / "alias"
                    args["transaction"].symlink_to(
                        self.transaction, target_is_directory=True
                    )
                elif case == "expiry":
                    from unittest.mock import patch

                    with (
                        patch.object(
                            upgrade.time,
                            "time_ns",
                            return_value=(self.now + 7200000) * 1000000,
                        ),
                        self.assertRaises(upgrade.UpgradeError),
                    ):
                        upgrade.publish(**args)
                    continue
                else:
                    root = (
                        self.source
                        if case == "source"
                        else self.transaction
                        / ("successor" if case == "candidate" else "checkpoint")
                    )
                    with (root / "ledger.sqlite").open("ab") as stream:
                        stream.write(b"changed")
                before = files(self.source)
                with self.assertRaises((upgrade.UpgradeError, OSError)):
                    upgrade.publish(**args)
                self.assertEqual(files(self.source), before)
                self.assertTrue((self.transaction / "checkpoint").is_dir())

    def test_interruption_before_exchange_retries_exact_staged_keys(self):
        from unittest.mock import patch

        receipt = self.stage()
        args = self.publish_args()
        with (
            patch.object(upgrade, "_exchange", side_effect=OSError("before exchange")),
            self.assertRaises(OSError),
        ):
            upgrade.publish(**args)
        self.assertEqual(files(self.source), self.before)
        self.assertEqual(
            upgrade.inventory_digest(self.transaction / "successor"),
            receipt["successor_sha256"],
        )
        self.assertEqual(upgrade.publish(**args)["state"], "published")

    def test_post_activation_effects_refuse_recovery_and_never_rewind(self):
        self.stage()
        args = self.publish_args()
        upgrade.publish(**args)
        with (self.source / "ledger.sqlite").open("ab") as stream:
            stream.write(b"synthetic-effect")
        before = files(self.source)
        with self.assertRaisesRegex(upgrade.UpgradeError, "ambiguous_state"):
            upgrade.publish(**args)
        self.assertEqual(files(self.source), before)
        self.assertEqual(files(self.transaction / "checkpoint"), self.before)

    def test_validly_signed_duplicate_candidate_profiles_rejected(self):
        from daimon_matrix.operator_capabilities import (
            create_operator_capability_binding,
        )

        self.stage()
        candidate = self.transaction / "successor"
        bundle = json.loads((candidate / "runtime.json").read_bytes())
        custody = EncryptedKeystore(candidate / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        bundle["capabilities"][1] = bundle["capabilities"][0]
        bundle["operator_capability_binding"] = create_operator_capability_binding(
            runtime_id=bundle["runtime_id"],
            runtime_label=bundle["runtime_label"],
            being_ref=bundle["manifest"]["being_ref"],
            origin=bundle["local_origin"],
            signing_seed=custody.secrets[bundle["keystore"]["signing_slot"]],
            capability_rows=bundle["capabilities"],
        )
        (candidate / "runtime.json").write_bytes(upgrade.canonical_bytes(bundle))
        ready = json.loads((self.transaction / "ready.json").read_bytes())
        ready["successor_sha256"] = upgrade.inventory_digest(candidate)
        (self.transaction / "ready.json").write_bytes(upgrade.canonical_bytes(ready))
        # Verify the named semantic guard, not merely the upgrader's deliberately
        # generic child-process error (which also covers invalid JSON).
        from daimon_matrix.runtime import RuntimeError, load_runtime

        with self.assertRaisesRegex(RuntimeError, "^duplicate_runtime_slot$"):
            load_runtime(
                candidate,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: time.time_ns() // 1000000,
            )
        evidence = upgrade._snapshot(self.parent)
        with self.assertRaisesRegex(upgrade.UpgradeError, "validation_rejected"):
            upgrade.publish(**self.publish_args())
        self.assertEqual(upgrade._snapshot(self.parent), evidence)
        self.assertEqual(files(self.source), self.before)

    def test_partial_publication_receipt_is_recoverable_without_rewind(self):
        from unittest.mock import patch

        receipt = self.stage()
        args: dict[str, Any] = dict(
            source=self.source,
            transaction=self.transaction,
            expected_receipt_sha256=hashlib.sha256(
                (self.transaction / "ready.json").read_bytes()
            ).hexdigest(),
            password=PASSWORD,
            externally_quiesced=True,
        )
        original = upgrade._write

        def partial(path, data):
            if path.name == "published.json" or path.name.startswith(".published-"):
                original(path, data[:10])
                raise OSError("synthetic interrupted receipt write")
            original(path, data)

        with (
            patch.object(upgrade, "_write", side_effect=partial),
            self.assertRaises(OSError),
        ):
            upgrade.publish(**args)
        self.assertEqual(
            upgrade.inventory_digest(self.source), receipt["successor_sha256"]
        )
        self.assertEqual(upgrade.publish(**args)["state"], "published")
        self.assertEqual(files(self.transaction / "checkpoint"), self.before)

    def test_intentionally_noncanonical_legacy_bundle_refuses_at_parser(self):
        from unittest.mock import patch

        (self.source / "runtime.json").write_text(json.dumps(self.bundle))
        snapshot = upgrade._snapshot(self.source)
        self.assertNotEqual(
            snapshot["runtime.json"], upgrade.canonical_bytes(self.bundle)
        )
        run = subprocess.run
        failures = []

        def observed(*args, **kwargs):
            result = run(*args, **kwargs)
            if result.returncode:
                failures.append(result.stderr)
            return result

        with (
            patch.object(upgrade.subprocess, "run", side_effect=observed),
            self.assertRaisesRegex(
                upgrade.UpgradeError, "^upgrade_runtime_validation_rejected$"
            ),
        ):
            self.stage()
        self.assertEqual(len(failures), 1)
        self.assertIn(b"runtime_bundle_not_canonical", failures[0])
        self.assertEqual(upgrade._snapshot(self.source), snapshot)
        self.assertEqual(upgrade._snapshot(self.transaction / "checkpoint"), snapshot)
        self.assertFalse((self.transaction / "ready.json").exists())

    def test_expired_legacy_authorization_cannot_be_extended_by_conversion(self):
        from daimon_matrix.local_api import create_capability

        row = self.bundle["capabilities"][0]
        custody = EncryptedKeystore(self.source / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        row["descriptor"] = create_capability(
            custody.secrets[row["secret_slot"]],
            client_id=row["descriptor"]["client_id"],
            methods=row["descriptor"]["methods"],
            not_before_ms=self.now - 20000,
            not_after_ms=self.now - 10000,
        ).descriptor
        (self.source / "runtime.json").write_bytes(upgrade.canonical_bytes(self.bundle))
        before = upgrade._snapshot(self.source)
        # The real pinned loader accepts these canonical bindings; usability is
        # the upgrader's responsibility, not a JSON-parser rejection.
        upgrade._validate(self.source, LEGACY, PASSWORD)
        self.assertEqual(upgrade._snapshot(self.source), before)
        with self.assertRaisesRegex(
            upgrade.UpgradeError, "^upgrade_legacy_authorization_expired$"
        ):
            self.stage()
        self.assertEqual(upgrade._snapshot(self.source), before)
        self.assertFalse(self.transaction.exists())

    def set_legacy_lifecycle(self, *, before, after, status="active", index=None):
        from daimon_matrix.local_api import create_capability

        custody = EncryptedKeystore(self.source / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        rows = self.bundle["capabilities"]
        for row in rows if index is None else [rows[index]]:
            descriptor = row["descriptor"]
            row["descriptor"] = create_capability(
                custody.secrets[row["secret_slot"]],
                client_id=descriptor["client_id"],
                methods=descriptor["methods"],
                not_before_ms=before,
                not_after_ms=after,
                status=status,
            ).descriptor
        (self.source / "runtime.json").write_bytes(upgrade.canonical_bytes(self.bundle))

    def test_canonical_legacy_lifecycle_refuses_each_required_row(self):
        from unittest.mock import patch

        for index in (0, 1):
            for case, before, after, status, reason in (
                ("expired", -20000, -10000, "active", "expired"),
                ("exact-not-after", -20000, 0, "active", "expired"),
                ("revoked", -20000, 3600000, "revoked", "inactive"),
                ("not-yet-valid", 1, 3600000, "active", "not_yet_valid"),
            ):
                with self.subTest(index=index, case=case):
                    self.setUp()
                    self.set_legacy_lifecycle(
                        before=self.now + before,
                        after=self.now + after,
                        status=status,
                        index=index,
                    )
                    snapshot = upgrade._snapshot(self.source)
                    upgrade._validate(self.source, LEGACY, PASSWORD)
                    self.assertEqual(upgrade._snapshot(self.source), snapshot)
                    with (
                        patch.object(
                            upgrade.time, "time_ns", return_value=self.now * 1000000
                        ),
                        self.assertRaisesRegex(
                            upgrade.UpgradeError,
                            "^upgrade_legacy_authorization_" + reason + "$",
                        ),
                    ):
                        self.stage()
                    self.assertEqual(upgrade._snapshot(self.source), snapshot)
                    self.assertFalse(self.transaction.exists())

    def test_canonical_legacy_valid_boundaries_publish(self):
        from unittest.mock import patch

        for offset in (0, 1, 3599999):
            with self.subTest(offset=offset):
                self.setUp()
                self.set_legacy_lifecycle(
                    before=self.now - offset, after=self.now - offset + 3600000
                )
                snapshot = upgrade._snapshot(self.source)
                with patch.object(
                    upgrade.time, "time_ns", return_value=self.now * 1000000
                ):
                    ready = self.stage()
                    result = upgrade.publish(**self.publish_args())
                self.assertEqual(result["state"], "published")
                self.assertEqual(
                    upgrade._snapshot(self.transaction / "checkpoint"), snapshot
                )
                self.assertEqual(
                    upgrade.inventory_digest(self.source), ready["successor_sha256"]
                )
                upgrade._validate(
                    self.source,
                    Path(upgrade.__file__).resolve().parent.parent,
                    PASSWORD,
                )

    def test_stage_expiry_crossing_validation_or_issuance_refuses(self):
        from unittest.mock import patch

        for point in (
            "validation",
            "custody-open",
            "issuance",
            "successor",
            "final-cas",
        ):
            with self.subTest(point=point):
                self.setUp()
                deadline = self.now + 60000
                self.set_legacy_lifecycle(before=self.now - 1000, after=deadline)
                snapshot = upgrade._snapshot(self.source)
                clock = [self.now]
                validate = upgrade._validate
                create = upgrade.create_capability
                open_store = EncryptedKeystore.open
                inventory = upgrade.inventory_digest
                validated = [False]

                def custody_open(
                    store,
                    *args,
                    open_store=open_store,
                    point=point,
                    clock=clock,
                    deadline=deadline,
                    **kwargs,
                ):
                    result = open_store(store, *args, **kwargs)
                    if point == "custody-open":
                        clock[0] = deadline
                    return result

                def cas(
                    root,
                    inventory=inventory,
                    point=point,
                    validated=validated,
                    clock=clock,
                    deadline=deadline,
                ):
                    result = inventory(root)
                    if point == "final-cas" and validated[0] and root == self.source:
                        clock[0] = deadline
                    return result

                def validation(
                    root,
                    code,
                    password,
                    validate=validate,
                    validated=validated,
                    point=point,
                    clock=clock,
                    deadline=deadline,
                ):
                    validate(root, code, password)
                    if root.name == "successor":
                        validated[0] = True
                    if root.name == point:
                        clock[0] = deadline

                def issuance(
                    *args,
                    create=create,
                    point=point,
                    clock=clock,
                    deadline=deadline,
                    **kwargs,
                ):
                    result = create(*args, **kwargs)
                    if point == "issuance":
                        clock[0] = deadline
                    return result

                with (
                    patch.object(
                        upgrade.time,
                        "time_ns",
                        side_effect=lambda clock=clock: clock[0] * 1000000,
                    ),
                    patch.object(upgrade, "_validate", side_effect=validation),
                    patch.object(upgrade, "create_capability", side_effect=issuance),
                    patch.object(EncryptedKeystore, "open", new=custody_open),
                    patch.object(upgrade, "inventory_digest", side_effect=cas),
                    self.assertRaisesRegex(
                        upgrade.UpgradeError, "^upgrade_legacy_authorization_expired$"
                    ),
                ):
                    self.stage()
                self.assertEqual(upgrade._snapshot(self.source), snapshot)
                self.assertEqual(
                    upgrade._snapshot(self.transaction / "checkpoint"), snapshot
                )
                self.assertFalse((self.transaction / "ready.json").exists())
                if point == "validation":
                    self.assertFalse((self.transaction / "successor").exists())
                elif point in ("custody-open", "issuance"):
                    self.assertEqual(
                        (self.transaction / "successor/custody.json").read_bytes(),
                        snapshot["custody.json"],
                    )

    def test_issuance_uses_fresh_time_after_legacy_validation(self):
        from unittest.mock import patch

        clock = [self.now - 1000]
        validate = upgrade._validate

        def delayed(root, code, password):
            validate(root, code, password)
            if root.name == "validation":
                clock[0] += 1000

        with (
            patch.object(
                upgrade.time,
                "time_ns",
                side_effect=lambda clock=clock: clock[0] * 1000000,
            ),
            patch.object(upgrade, "_validate", side_effect=delayed),
        ):
            self.stage()
        bundle = json.loads((self.transaction / "successor/runtime.json").read_bytes())
        self.assertEqual(
            {r["descriptor"]["not_before_ms"] for r in bundle["capabilities"]},
            {clock[0]},
        )

    def test_forward_publication_rechecks_legacy_and_new_deadlines(self):
        from unittest.mock import patch

        for authority in ("legacy", "new"):
            for point in ("before-publish", "validation", "final-cas"):
                with self.subTest(authority=authority, point=point):
                    self.setUp()
                    deadline = self.now + 60000
                    self.set_legacy_lifecycle(
                        before=self.now - 1000,
                        after=deadline if authority == "legacy" else self.now + 3600000,
                    )
                    self.stage(
                        expires_at_ms=deadline
                        if authority == "new"
                        else self.now + 3600000
                    )
                    args = self.publish_args()
                    evidence = upgrade._snapshot(self.parent)
                    clock = [deadline if point == "before-publish" else self.now]
                    validate, inventory = upgrade._validate, upgrade.inventory_digest
                    validated = [False]

                    def delayed(
                        root,
                        code,
                        password,
                        validate=validate,
                        validated=validated,
                        point=point,
                        clock=clock,
                        deadline=deadline,
                    ):
                        validate(root, code, password)
                        validated[0] = True
                        if point == "validation":
                            clock[0] = deadline

                    def cas(
                        root,
                        inventory=inventory,
                        point=point,
                        validated=validated,
                        clock=clock,
                        deadline=deadline,
                    ):
                        result = inventory(root)
                        if (
                            point == "final-cas"
                            and validated[0]
                            and root.name == "successor"
                        ):
                            clock[0] = deadline
                        return result

                    reason = (
                        "upgrade_legacy_authorization_expired"
                        if authority == "legacy"
                        else "upgrade_authorization_expired"
                    )
                    with (
                        patch.object(
                            upgrade.time,
                            "time_ns",
                            side_effect=lambda clock=clock: clock[0] * 1000000,
                        ),
                        patch.object(upgrade, "_validate", side_effect=delayed),
                        patch.object(upgrade, "inventory_digest", side_effect=cas),
                        patch.object(
                            upgrade, "_exchange", wraps=upgrade._exchange
                        ) as exchange,
                        self.assertRaisesRegex(
                            upgrade.UpgradeError, "^" + reason + "$"
                        ),
                    ):
                        upgrade.publish(**args)
                    exchange.assert_not_called()
                    self.assertEqual(upgrade._snapshot(self.parent), evidence)

    def test_committed_forward_replay_after_all_expiry_never_reissues(self):
        from unittest.mock import patch

        for lost_return in (False, True):
            with self.subTest(lost_return=lost_return):
                self.setUp()
                ready = self.stage()
                args = self.publish_args()
                exchange = upgrade._exchange

                def interrupted(left, right, exchange=exchange):
                    exchange(left, right)
                    raise OSError("lost return after real exchange")

                if lost_return:
                    with (
                        patch.object(upgrade, "_exchange", side_effect=interrupted),
                        self.assertRaises(OSError),
                    ):
                        upgrade.publish(**args)
                else:
                    upgrade.publish(**args)
                snapshot = upgrade._snapshot(self.source)
                checkpoint = upgrade._snapshot(self.transaction / "checkpoint")
                expiry = max(
                    ready["expires_at_ms"],
                    *(
                        r["descriptor"]["not_after_ms"]
                        for r in self.bundle["capabilities"]
                    ),
                )
                with (
                    patch.object(
                        upgrade.time, "time_ns", return_value=(expiry + 1) * 1000000
                    ),
                    patch.object(
                        upgrade,
                        "create_capability",
                        side_effect=AssertionError("no issuance"),
                    ),
                    patch.object(
                        EncryptedKeystore,
                        "rotate",
                        side_effect=AssertionError("no rotation"),
                    ),
                    patch.object(
                        upgrade, "_exchange", side_effect=AssertionError("no exchange")
                    ),
                ):
                    result = upgrade.publish(**args)
                    self.assertEqual(upgrade.publish(**args), result)
                self.assertEqual(result["counter_after"], 2)
                self.assertEqual(upgrade._snapshot(self.source), snapshot)
                self.assertEqual(
                    upgrade._snapshot(self.transaction / "checkpoint"), checkpoint
                )

    def test_cli_uses_password_fd_and_digest_bound_request(self):
        request = dict(
            source=str(self.source),
            transaction=str(self.transaction),
            legacy_source=str(LEGACY),
            legacy_sha256=upgrade.LEGACY_SOURCE_SHA256,
            expected_source_sha256=upgrade.inventory_digest(self.source),
            expected_counter=self.bundle["keystore"]["counter"],
            expected_control_head=self.bundle["control_head"],
            expected_being_ref=self.bundle["manifest"]["being_ref"],
            expected_origin=self.bundle["local_origin"],
            expires_at_ms=self.now + 3600000,
        )
        path = self.parent / "request.json"
        path.write_text(json.dumps(request))
        path.chmod(0o600)
        read, write = os.pipe()
        os.write(write, PASSWORD)
        os.close(write)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.operator_runtime_upgrade",
                    "stage",
                    "--request",
                    str(path),
                    "--request-sha256",
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    "--password-fd",
                    str(read),
                    "--externally-quiesced",
                ],
                pass_fds=(read,),
                capture_output=True,
            )
        finally:
            os.close(read)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.transaction / "ready.json").exists())
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertEqual(files(self.source), self.before)

    def test_failed_old_validation_never_mutates_checkpoint(self):
        (self.source / "ledger.sqlite").unlink()
        before = files(self.source)
        with self.assertRaises(upgrade.UpgradeError):
            self.stage()
        self.assertEqual(files(self.source), before)
        self.assertEqual(files(self.transaction / "checkpoint"), before)
        self.assertFalse((self.transaction / "ready.json").exists())

    def test_inventory_binds_empty_directories(self):
        before = upgrade.inventory_digest(self.source)
        (self.source / "unexpected-empty").mkdir(mode=0o700)
        self.assertNotEqual(before, upgrade.inventory_digest(self.source))

    def test_atomic_publish_and_exact_retry_after_lost_return(self):
        from unittest.mock import patch

        receipt = self.stage()
        digest = hashlib.sha256(
            (self.transaction / "ready.json").read_bytes()
        ).hexdigest()
        args: dict[str, Any] = dict(
            source=self.source,
            transaction=self.transaction,
            expected_receipt_sha256=digest,
            password=PASSWORD,
            externally_quiesced=True,
        )
        real_exchange = upgrade._exchange

        def interrupted(*args):
            real_exchange(*args)
            raise OSError("synthetic lost return after actual exchange")

        with (
            patch.object(upgrade, "_exchange", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            upgrade.publish(**args)
        self.assertEqual(
            upgrade.inventory_digest(self.source), receipt["successor_sha256"]
        )
        self.assertEqual(files(self.transaction / "successor"), self.before)
        self.assertEqual(files(self.transaction / "checkpoint"), self.before)
        result = upgrade.publish(**args)
        self.assertEqual(result["state"], "published")
        self.assertEqual(upgrade.publish(**args), result)
        self.assertEqual(
            upgrade.inventory_digest(self.source), receipt["successor_sha256"]
        )
        self.assertTrue((self.transaction / "published.json").exists())

    def test_stage_preserves_identity_history_and_rotates_custody_once(self):
        receipt = self.stage()
        self.assertEqual(files(self.source), self.before)
        self.assertEqual(files(self.transaction / "checkpoint"), self.before)
        candidate = self.transaction / "successor"
        after = json.loads((candidate / "runtime.json").read_bytes())
        for field in self.bundle.keys() - {"capabilities", "keystore"}:
            self.assertEqual(after[field], self.bundle[field], field)
        self.assertEqual(
            after["keystore"]["counter"], self.bundle["keystore"]["counter"] + 1
        )
        old = EncryptedKeystore(self.source / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        new = EncryptedKeystore(candidate / "custody.json").open(
            lambda: bytearray(PASSWORD)
        )
        retired = {r["secret_slot"] for r in self.bundle["capabilities"]}
        for slot in old.secrets.keys() - retired:
            self.assertEqual(old.secrets[slot], new.secrets[slot])
        self.assertFalse(retired & new.secrets.keys())
        self.assertEqual(
            len({new.secrets[r["secret_slot"]] for r in after["capabilities"]}), 12
        )
        for filename in self.before:
            if ".sqlite" in filename or "transport-custody" in filename:
                self.assertEqual(files(candidate)[filename], self.before[filename])
        self.assertEqual(
            receipt["source_sha256"], upgrade.inventory_digest(self.source)
        )
        self.assertEqual(
            receipt["successor_sha256"], upgrade.inventory_digest(candidate)
        )
        self.assertTrue((self.transaction / "ready.json").is_file())
