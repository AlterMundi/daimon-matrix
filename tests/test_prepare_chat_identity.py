"""Offline first-chat preparation through installed production APIs."""

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.authority_epochs import RootHistoryAuthority
from daimon_matrix.messaging_config import _public_identity, verify_public_binding
from daimon_matrix.native_egress import closed_visibility
from daimon_matrix.runtime import load_runtime
from tools.prepare_chat_identity import now, prepare


class ChatIdentityTests(unittest.TestCase):
    def test_offline_v2_identity_public_proof_and_no_reinitialization(self):
        with tempfile.TemporaryDirectory(prefix="dm-chat-") as directory:
            parent = Path(directory).resolve()
            parent.chmod(0o700)
            output = parent / "owner"
            with (
                patch("socket.socket.bind", side_effect=AssertionError("listener")),
                patch(
                    "socket.create_connection", side_effect=AssertionError("network")
                ),
            ):
                public_path = prepare(
                    output,
                    label="chat-test",
                    body_ref="hermes:chat-test",
                    principal_id="chat-test@local",
                )
            raw = public_path.read_bytes()
            public = json.loads(raw)
            password = (output / "body.password").read_bytes()
            for secret in (password, (output / "holder.password").read_bytes()):
                self.assertNotIn(secret.hex().encode(), raw)
                self.assertNotIn(base64.urlsafe_b64encode(secret).rstrip(b"="), raw)
            runtime = load_runtime(
                output / "package" / "runtime",
                "runtime.json",
                lambda: bytearray(password),
                clock=now,
                egress=closed_visibility(clock=now, catalog_mode="migrate"),
            )
            self.assertIsInstance(
                runtime.service.ledger.authority, RootHistoryAuthority
            )
            self.assertEqual(len(runtime.service.ledger.authority.successors), 1)
            self.assertEqual(runtime.service.ledger.events(), [])
            self.assertFalse(runtime.socket_path.exists())
            self.assertFalse(runtime.egress.release_enabled)
            verify_public_binding(
                _public_identity(
                    runtime.service.ledger.authority,
                    runtime.service.origin,
                    runtime.service.runtime_id,
                    runtime.service.runtime_label,
                    now(),
                ),
                runtime.service.signer.public_key,
                public["document"],
                public["binding"],
            )
            before = {
                path.relative_to(output): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.rglob("*")
                if path.is_file()
            }
            with self.assertRaises(FileExistsError):
                prepare(
                    output,
                    label="chat-test",
                    body_ref="hermes:chat-test",
                    principal_id="chat-test@local",
                )
            after = {
                path.relative_to(output): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)
            for path in output.rglob("*"):
                self.assertFalse(path.stat().st_mode & 0o077, str(path))
