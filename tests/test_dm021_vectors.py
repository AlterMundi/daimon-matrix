from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.canonical import canonical_bytes, unb64url
from daimon_matrix.identity import (
    VerificationError,
    verify_binding_activation,
    verify_embodiment_credential,
    verify_genesis,
    verify_history_binding,
    verify_incarnation_authorization,
    verify_recovery,
    verify_successor,
)

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "vectors" / "identity" / "v1"
NOW = 1_800_000_000_000


def load(path: Path) -> Any:
    return json.loads(path.read_bytes())


class DM021VectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = load(VECTOR_ROOT / "index.json")
        self.valid = {
            name: load(VECTOR_ROOT / relative)
            for name, relative in self.index["valid"].items()
        }
        self.support = {
            name: load(VECTOR_ROOT / relative)
            for name, relative in self.index["support"].items()
        }
        self.negative = {
            name: load(VECTOR_ROOT / relative)
            for name, relative in self.index["negative"].items()
        }
        self.state = verify_genesis(self.valid["genesis"])

    def _verify_head(self, head: Any) -> bool:
        weave_root = ROOT / "vectors" / "weave" / "v1"
        event = load(weave_root / "configuration-proposal.json")
        weave_index = load(weave_root / "index.json")
        core = {
            key: value
            for key, value in event.items()
            if key not in {"content_hash", "signature"}
        }
        digest_hex = hashlib.sha256(canonical_bytes(core)).hexdigest()
        if head != self.index["accepted_head"] or head["content_hash"] != digest_hex:
            return False
        public = unb64url(weave_index["public_keys"][head["signer_key_id"]], length=32)
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                unb64url(event["signature"]["value"], length=64),
                b"daimon/weave/event/v1\x00" + bytes.fromhex(digest_hex),
            )
        except Exception:
            return False
        return True

    def _binding_arguments(self) -> dict[str, Any]:
        manifest = load(ROOT / "vectors" / "weave" / "v1" / "manifest.json")
        return {
            "manifest_bytes": canonical_bytes(manifest),
            "manifest_revision": manifest["revision"],
            "accepted_heads": [self.index["accepted_head"]],
            "verify_head": self._verify_head,
        }

    def test_every_vector_is_canonical_and_schema_valid(self) -> None:
        schema = load(ROOT / "schemas" / "identity" / "v1" / "artifact.schema.json")
        validator = Draft202012Validator(schema)
        files = [
            *(VECTOR_ROOT / relative for relative in self.index["valid"].values()),
            *(VECTOR_ROOT / relative for relative in self.index["support"].values()),
            *(VECTOR_ROOT / relative for relative in self.index["negative"].values()),
        ]
        for path in files:
            with self.subTest(path=path):
                value = load(path)
                self.assertEqual(path.read_bytes(), canonical_bytes(value) + b"\n")
                validator.validate(value)

    def test_every_valid_artifact_verifies_with_real_crypto(self) -> None:
        credential = self.valid["embodiment-credential"]
        verify_embodiment_credential(credential, self.state, at_ms=NOW)
        verify_incarnation_authorization(
            self.valid["incarnation-authorization"],
            credential,
            self.state,
            at_ms=NOW,
        )
        verify_successor(self.valid["root-rotation"], self.state)
        verify_successor(self.valid["recovery-policy"], self.state)
        verify_successor(self.valid["revocation"], self.state)
        branch_states = [
            verify_successor(self.support["fork-branch-a"], self.state),
            verify_successor(self.support["fork-branch-b"], self.state),
        ]
        verify_recovery(self.valid["recovery"], branch_states)
        verify_history_binding(
            self.valid["history-binding"],
            self.state,
            **self._binding_arguments(),
        )
        verify_binding_activation(
            self.valid["binding-activation"],
            self.valid["history-binding"],
            self.state,
        )

    def test_every_negative_artifact_fails_its_runtime_verifier(self) -> None:
        credential = self.valid["embodiment-credential"]
        branch_states = [
            verify_successor(self.support["fork-branch-a"], self.state),
            verify_successor(self.support["fork-branch-b"], self.state),
        ]
        checks: dict[str, Callable[[], object]] = {
            "genesis-missing-root-threshold": lambda: verify_genesis(
                self.negative["genesis-missing-root-threshold"]
            ),
            "credential-missing-acceptance": lambda: verify_embodiment_credential(
                self.negative["credential-missing-acceptance"],
                self.state,
                at_ms=NOW,
            ),
            "incarnation-missing-authorization": lambda: (
                verify_incarnation_authorization(
                    self.negative["incarnation-missing-authorization"],
                    credential,
                    self.state,
                    at_ms=NOW,
                )
            ),
            "rotation-missing-new-root-possession": lambda: verify_successor(
                self.negative["rotation-missing-new-root-possession"], self.state
            ),
            "recovery-policy-missing-old-recovery": lambda: verify_successor(
                self.negative["recovery-policy-missing-old-recovery"], self.state
            ),
            "revocation-missing-root-threshold": lambda: verify_successor(
                self.negative["revocation-missing-root-threshold"], self.state
            ),
            "recovery-omits-recovery-threshold": lambda: verify_recovery(
                self.negative["recovery-omits-recovery-threshold"], branch_states
            ),
            "binding-missing-root-threshold": lambda: verify_history_binding(
                self.negative["binding-missing-root-threshold"],
                self.state,
                **self._binding_arguments(),
            ),
            "activation-missing-root-threshold": lambda: verify_binding_activation(
                self.negative["activation-missing-root-threshold"],
                self.valid["history-binding"],
                self.state,
            ),
        }
        self.assertEqual(set(checks), set(self.negative))
        for name, check in checks.items():
            with self.subTest(name=name), self.assertRaises(VerificationError):
                check()

    def test_regeneration_is_byte_identical(self) -> None:
        before = {
            path.relative_to(VECTOR_ROOT): path.read_bytes()
            for path in VECTOR_ROOT.rglob("*.json")
        }
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "generate_dm021_vectors.py")],
            cwd=ROOT,
            env=environment,
            check=True,
        )
        after = {
            path.relative_to(VECTOR_ROOT): path.read_bytes()
            for path in VECTOR_ROOT.rglob("*.json")
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
