from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.operator_genesis import (
    PENDING_CONTROL_HEAD,
    GenesisError,
    aggregate_intent,
    create_holder_package,
)
from daimon_matrix.operator_rebirth import RebirthError, create_replacement_root_holder
from tests.test_dm022_ledger import RootLedgerFixture


def _reader(value: bytes):  # type: ignore[no-untyped-def]
    return lambda: bytearray(value)


class DistributedGenesisTests(TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="dm-genesis-test-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _invoke(
        self, arguments: Sequence[str], password: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        descriptors: tuple[int, ...] = ()
        values = list(arguments)
        reader = -1
        if password is not None:
            reader, writer = os.pipe()
            os.write(writer, password)
            os.close(writer)
            descriptors = (reader,)
            values = [
                str(reader) if value == "{password}" else value for value in values
            ]
        try:
            return subprocess.run(
                [sys.executable, "-m", "daimon_matrix.operator_genesis", *values],
                cwd=Path(__file__).resolve().parents[1],
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                },
                pass_fds=descriptors,
                capture_output=True,
                check=False,
            )
        finally:
            if reader >= 0:
                os.close(reader)

    def test_cli_uses_six_isolated_holder_processes_and_keyless_aggregation(
        self,
    ) -> None:
        holders: list[tuple[Path, bytes]] = []
        descriptors: list[Path] = []
        for role in ("root", "recovery"):
            for index in range(3):
                package = self.root / f"{role}-{index}"
                password = f"genesis-{role}-{index}-password".encode()
                result = self._invoke(
                    [
                        "create-holder",
                        "--role",
                        role,
                        "--password-fd",
                        "{password}",
                        "--output",
                        str(package),
                    ],
                    password,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                holders.append((package, password))
                descriptors.append(package / "descriptor.json")
                contents = EncryptedKeystore(package / "holder.json").open(
                    _reader(password),
                    minimum_counter=1,
                    required_control_head=PENDING_CONTROL_HEAD,
                )
                self.assertEqual(len(contents.secrets), 1)

        intent_path = self.root / "intent.json"
        result = self._invoke(
            [
                "create-intent",
                *(item for path in descriptors for item in ("--descriptor", str(path))),
                "--root-threshold",
                "2",
                "--recovery-threshold",
                "2",
                "--output",
                str(intent_path),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

        share_paths: list[Path] = []
        for index in (0, 1, 3, 4):
            package, password = holders[index]
            share = self.root / f"share-{index}.json"
            result = self._invoke(
                [
                    "sign",
                    "--intent",
                    str(intent_path),
                    "--holder",
                    str(package),
                    "--password-fd",
                    "{password}",
                    "--output",
                    str(share),
                ],
                password,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            share_paths.append(share)

        genesis_path = self.root / "genesis.json"
        result = self._invoke(
            [
                "aggregate",
                "--intent",
                str(intent_path),
                *(item for path in share_paths for item in ("--share", str(path))),
                "--output",
                str(genesis_path),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        public = b"".join(
            path.read_bytes()
            for path in [intent_path, *descriptors, *share_paths, genesis_path]
        )
        for package, _password in holders:
            self.assertNotIn((package / "holder.json").read_bytes(), public)

        intent = json.loads(intent_path.read_bytes())
        shares = [json.loads(path.read_bytes()) for path in share_paths]
        with self.assertRaisesRegex(GenesisError, "threshold_rejected"):
            aggregate_intent(intent, shares[:1] + shares[2:3])
        with self.assertRaisesRegex(GenesisError, "threshold_rejected"):
            aggregate_intent(intent, [shares[0], shares[0], shares[2], shares[3]])

    def test_holder_package_is_atomic_across_sigkill_at_commit(self) -> None:
        target = self.root / "recovery-holder"
        password = b"atomic-genesis-holder-password"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import os
import sys
from pathlib import Path
from unittest import mock
from daimon_matrix.operator_genesis import create_holder_package
with mock.patch(
    "daimon_matrix.operator_genesis.os.replace",
    side_effect=lambda *_args: os.kill(os.getpid(), 9),
):
    create_holder_package(
        Path(sys.argv[1]), "recovery", lambda: bytearray.fromhex(sys.argv[2])
    )
""",
                str(target),
                password.hex(),
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            },
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, -9)
        self.assertFalse(target.exists())
        receipt = create_holder_package(target, "recovery", _reader(password))
        self.assertEqual(json.loads((target / "descriptor.json").read_bytes()), receipt)

    def test_holder_retry_recovers_receipt_after_final_rename(self) -> None:
        target = self.root / "post-rename-root-holder"
        password = b"post-rename-genesis-holder-password"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import os
import sys
from pathlib import Path
from unittest import mock
import daimon_matrix.operator_genesis as genesis
target = Path(sys.argv[1])
real_fsync = genesis._fsync_directory
def kill_after_rename(path):
    if Path(path) == target.parent and target.exists():
        os.kill(os.getpid(), 9)
    real_fsync(path)
with mock.patch(
    "daimon_matrix.operator_genesis._fsync_directory",
    side_effect=kill_after_rename,
):
    genesis.create_holder_package(
        target, "root", lambda: bytearray.fromhex(sys.argv[2])
    )
""",
                str(target),
                password.hex(),
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            },
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, -9)
        self.assertTrue(target.is_dir())
        committed = json.loads((target / "descriptor.json").read_bytes())
        self.assertEqual(
            create_holder_package(target, "root", _reader(password)), committed
        )
        with self.assertRaisesRegex(GenesisError, "genesis_holder_conflict"):
            create_holder_package(
                target, "root", _reader(b"wrong-post-rename-password")
            )
        with self.assertRaisesRegex(GenesisError, "genesis_holder_conflict"):
            create_holder_package(target, "recovery", _reader(password))


class ReplacementHolderAtomicityTests(RootLedgerFixture):
    def test_replacement_holder_package_retries_after_commit_kill(self) -> None:
        target = self.root_path / "replacement-holder"
        password = b"atomic-replacement-holder-password"
        authority_path = self.root_path / "authority.json"
        authority_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.operator.authority/v1",
                    "control_artifacts": [self.genesis],
                    "control_head": self.state.head,
                    "manifest": self.manifest.value,
                    "credentials": list(self.credentials.values()),
                    "incarnations": list(self.incarnations.values()),
                }
            )
        )
        authority_path.chmod(0o600)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import json
import os
import sys
from pathlib import Path
from unittest import mock
from daimon_matrix.operator_rebirth import (
    authority_from_document,
    create_replacement_root_holder,
)
authority = authority_from_document(json.loads(Path(sys.argv[2]).read_bytes()))
with mock.patch(
    "daimon_matrix.operator_rebirth.os.replace",
    side_effect=lambda *_args: os.kill(os.getpid(), 9),
):
    create_replacement_root_holder(
        Path(sys.argv[1]), authority, lambda: bytearray.fromhex(sys.argv[3])
    )
""",
                str(target),
                str(authority_path),
                password.hex(),
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            },
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, -9)
        self.assertFalse(target.exists())
        receipt = create_replacement_root_holder(
            target, self.authority, _reader(password)
        )
        self.assertEqual(
            canonical_bytes(json.loads((target / "descriptor.json").read_bytes())),
            canonical_bytes(receipt),
        )

    def test_replacement_holder_retry_recovers_after_final_rename(self) -> None:
        target = self.root_path / "post-rename-replacement-holder"
        password = b"post-rename-replacement-holder-password"
        authority_path = self.root_path / "post-rename-authority.json"
        authority_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.operator.authority/v1",
                    "control_artifacts": [self.genesis],
                    "control_head": self.state.head,
                    "manifest": self.manifest.value,
                    "credentials": list(self.credentials.values()),
                    "incarnations": list(self.incarnations.values()),
                }
            )
        )
        authority_path.chmod(0o600)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                """
import json
import os
import sys
from pathlib import Path
from unittest import mock
import daimon_matrix.operator_rebirth as rebirth
target = Path(sys.argv[1])
authority = rebirth.authority_from_document(
    json.loads(Path(sys.argv[2]).read_bytes())
)
real_fsync = rebirth._fsync_directory
def kill_after_rename(path):
    if Path(path) == target.parent and target.exists():
        os.kill(os.getpid(), 9)
    real_fsync(path)
with mock.patch(
    "daimon_matrix.operator_rebirth._fsync_directory",
    side_effect=kill_after_rename,
):
    rebirth.create_replacement_root_holder(
        target, authority, lambda: bytearray.fromhex(sys.argv[3])
    )
""",
                str(target),
                str(authority_path),
                password.hex(),
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                **os.environ,
                "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
            },
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, -9)
        self.assertTrue(target.is_dir())
        committed = json.loads((target / "descriptor.json").read_bytes())
        self.assertEqual(
            create_replacement_root_holder(target, self.authority, _reader(password)),
            committed,
        )
        with self.assertRaisesRegex(RebirthError, "rebirth_holder_conflict"):
            create_replacement_root_holder(
                target,
                self.authority,
                _reader(b"wrong-post-rename-password"),
            )
