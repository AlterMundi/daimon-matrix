from __future__ import annotations

import json
import os
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.keystore import (
    EncryptedKeystore,
    KeystoreConflictError,
    KeystoreError,
    KeystoreRollbackError,
)

PASSWORD = b"synthetic-custody-password"
REPLACEMENT = b"synthetic-replacement-password"


def password(value: bytes = PASSWORD) -> Callable[[], bytearray]:
    return lambda: bytearray(value)


class EncryptedKeystoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="dm021-keystore-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.path = self.root / "custody.json"
        self.store = EncryptedKeystore.create(
            self.path,
            password(),
            control_head="dm:identity:v1:genesis",
            secrets={"root-a": b"A" * 32, "recovery-a": b"R" * 32},
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_create_open_rotate_and_no_plaintext(self) -> None:
        raw = self.path.read_bytes()
        self.assertNotIn(b"A" * 32, raw)
        self.assertNotIn(b"R" * 32, raw)
        opened = self.store.open(password())
        self.assertEqual(opened.counter, 1)
        self.assertEqual(opened.secrets["root-a"], b"A" * 32)

        rotated = self.store.rotate(
            password(),
            password(REPLACEMENT),
            expected_counter=1,
            control_head="dm:identity:v1:rotation",
        )
        self.assertEqual(rotated.counter, 2)
        with self.assertRaises(KeystoreError):
            self.store.open(password())
        self.assertEqual(
            self.store.open(
                password(REPLACEMENT),
                minimum_counter=2,
                required_control_head="dm:identity:v1:rotation",
            ).counter,
            2,
        )

    def test_wrong_password_tamper_and_truncation_fail_closed(self) -> None:
        with self.assertRaises(KeystoreError):
            self.store.open(password(b"this-is-the-wrong-password"))

        original = self.path.read_bytes()
        document = json.loads(original)
        ciphertext = document["ciphertext"]
        document["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        self.path.write_bytes(canonical_bytes(document) + b"\n")
        self.path.chmod(0o600)
        with self.assertRaises(KeystoreError):
            self.store.open(password())

        self.path.write_bytes(original[: len(original) // 2])
        self.path.chmod(0o600)
        with self.assertRaises(KeystoreError):
            self.store.open(password())

    def test_duplicate_keys_and_unbounded_kdf_parameters_fail_before_decrypt(
        self,
    ) -> None:
        original = self.path.read_bytes()
        duplicated = original.replace(
            b'{"aead":', b'{"schema":"dm.keystore/v1","aead":', 1
        )
        self.path.write_bytes(duplicated)
        self.path.chmod(0o600)
        with self.assertRaises(KeystoreError):
            self.store.open(password())

        document = json.loads(original)
        document["kdf"]["n"] = 2**30
        self.path.write_bytes(canonical_bytes(document) + b"\n")
        self.path.chmod(0o600)
        with self.assertRaises(KeystoreError):
            self.store.open(password())

    def test_unsafe_mode_and_symlink_fail_closed(self) -> None:
        self.path.chmod(0o644)
        with self.assertRaises(KeystoreError):
            self.store.open(password())
        self.path.chmod(0o600)

        link = self.root / "linked-custody.json"
        link.symlink_to(self.path)
        with self.assertRaises(KeystoreError):
            EncryptedKeystore(link).open(password())

    def test_concurrent_stale_writer_is_rejected(self) -> None:
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def writer(head: str) -> None:
            barrier.wait()
            try:
                self.store.rotate(
                    password(),
                    password(),
                    expected_counter=1,
                    control_head=head,
                )
            except KeystoreConflictError:
                outcomes.append("conflict")
            else:
                outcomes.append("committed")

        threads = [
            threading.Thread(target=writer, args=("dm:head:a",)),
            threading.Thread(target=writer, args=("dm:head:b",)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertCountEqual(outcomes, ["committed", "conflict"])
        self.assertEqual(self.store.open(password()).counter, 2)

    def test_interrupted_replace_preserves_previous_ciphertext(self) -> None:
        before = self.path.read_bytes()
        real_replace = os.replace

        def fail_target(source: Any, destination: Any) -> None:
            if Path(destination) == self.path:
                raise OSError("synthetic interrupted replace")
            real_replace(source, destination)

        with (
            mock.patch("daimon_matrix.keystore.os.replace", side_effect=fail_target),
            self.assertRaises(OSError),
        ):
            self.store.rotate(
                password(),
                password(REPLACEMENT),
                expected_counter=1,
                control_head="dm:head:interrupted",
            )
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".custody.json.tmp-*")), [])
        self.assertEqual(self.store.open(password()).counter, 1)

    def test_backup_restore_reconciles_public_high_water(self) -> None:
        stale = self.root / "stale-backup.json"
        self.store.backup(stale, password())
        self.store.rotate(
            password(),
            password(),
            expected_counter=1,
            control_head="dm:identity:v1:rotation",
        )
        fresh_root = self.root / "fresh-host"
        fresh_root.mkdir(mode=0o700)
        with self.assertRaises(KeystoreRollbackError):
            EncryptedKeystore.restore(
                stale,
                fresh_root / "restored.json",
                password(),
                public_counter=2,
                public_control_head="dm:identity:v1:rotation",
            )

        current = self.root / "current-backup.json"
        self.store.backup(current, password(), minimum_counter=2)
        restored = EncryptedKeystore.restore(
            current,
            fresh_root / "restored.json",
            password(),
            public_counter=2,
            public_control_head="dm:identity:v1:rotation",
        )
        contents = restored.open(
            password(),
            minimum_counter=2,
            required_control_head="dm:identity:v1:rotation",
        )
        self.assertEqual(contents.secrets["root-a"], b"A" * 32)


if __name__ == "__main__":
    unittest.main()
