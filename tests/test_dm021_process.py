from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]

PROCESS_PROGRAM = r"""
import base64
import json
import sys
from pathlib import Path

from daimon_matrix.identity import create_genesis, verify_genesis
from daimon_matrix.keystore import EncryptedKeystore

payload = json.loads(sys.stdin.buffer.read())
decode = lambda value: base64.urlsafe_b64decode(value.encode("ascii"))
root = [decode(value) for value in payload["root"]]
recovery = [decode(value) for value in payload["recovery"]]
password = decode(payload["password"])
first = Path(payload["first"])
second = Path(payload["second"])
genesis = create_genesis(root, 2, recovery, 2, created_at_ms=1800000000000)
state = verify_genesis(genesis)
store = EncryptedKeystore.create(
    first / "custody.json",
    lambda: bytearray(password),
    control_head=state.head,
    secrets={"root-a": root[0], "recovery-a": recovery[0]},
)
backup = first / "backup.json"
store.backup(backup, lambda: bytearray(password))
restored = EncryptedKeystore.restore(
    backup,
    second / "custody.json",
    lambda: bytearray(password),
    public_counter=1,
    public_control_head=state.head,
)
contents = restored.open(
    lambda: bytearray(password),
    minimum_counter=1,
    required_control_head=state.head,
)
print(json.dumps({"being_ref": state.being_ref, "counter": contents.counter}))
"""


def synthetic(label: str) -> bytes:
    return hashlib.sha256(f"dm021-process:{label}".encode()).digest()


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


class SeparateProcessCustodyTests(unittest.TestCase):
    def test_secrets_enter_only_over_descriptor_and_never_leave_ciphertext(
        self,
    ) -> None:
        root = [synthetic("root-a"), synthetic("root-b"), synthetic("root-c")]
        recovery = [
            synthetic("recovery-a"),
            synthetic("recovery-b"),
            synthetic("recovery-c"),
        ]
        password = b"descriptor-only-test-password"
        with TemporaryDirectory(prefix="dm021-process-") as temporary:
            first = Path(temporary) / "first-host"
            second = Path(temporary) / "fresh-host"
            first.mkdir(mode=0o700)
            second.mkdir(mode=0o700)
            payload = {
                "first": str(first),
                "password": encode(password),
                "recovery": [encode(value) for value in recovery],
                "root": [encode(value) for value in root],
                "second": str(second),
            }
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(ROOT / "src")
            command = [sys.executable, "-c", PROCESS_PROGRAM]
            forbidden = [password, *root, *recovery]
            joined_command = "\x00".join(command).encode()
            joined_environment = "\x00".join(environment.values()).encode()
            for secret in forbidden:
                self.assertNotIn(secret, joined_command)
                self.assertNotIn(secret, joined_environment)

            result = subprocess.run(
                command,
                input=json.dumps(payload).encode(),
                cwd=ROOT,
                env=environment,
                check=True,
                capture_output=True,
            )
            report = json.loads(result.stdout)
            self.assertTrue(report["being_ref"].startswith("dm:being:v1:"))
            self.assertEqual(report["counter"], 1)
            self.assertEqual(result.stderr, b"")

            exported = b"".join(
                path.read_bytes()
                for path in Path(temporary).rglob("*")
                if path.is_file()
            )
            for secret in forbidden:
                self.assertNotIn(secret, result.stdout)
                self.assertNotIn(secret, result.stderr)
                self.assertNotIn(secret, exported)


if __name__ == "__main__":
    unittest.main()
