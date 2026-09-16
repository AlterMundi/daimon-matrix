"""Synthetic approval keys only; no human authentication/frontend claim."""

import hashlib
import json
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from daimon_matrix import execution_instruction as contract


def request(**changes):
    data = dict(
        schema="execution/v1",
        instruction_id="review-1",
        store_id="store:test",
        revision=1,
        predecessor=None,
        principal="human:test",
        being="being:test",
        embodiment="body:test",
        runner="runner:test",
        session="session:test",
        mode="periodic",
        start=100,
        end=200,
        interval=10,
        max_cycle_seconds=8,
        cleanup_seconds=2,
        max_cycles=10,
        max_effects=2,
        max_input_tokens=1000,
        max_output_tokens=200,
        provider="test",
        model="bounded-fake",
        task_sha256="a" * 64,
        scope=[
            dict(
                channel="channel:test",
                thread="thread:test",
                tool="messaging_inbox",
                action="review",
            )
        ],
    )
    return data | changes


def proof(key, action, payload, event="approval-1"):
    body = dict(
        purpose="execution/v1/" + action,
        event_id=event,
        principal="human:test",
        payload_sha256=hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        ).hexdigest(),
    )
    signature = key.sign(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hex()
    return body | {"signature": signature}


def verifier(key):
    return contract.ApprovalVerifier({"human:test": key.public_key()})


class InstructionTests(unittest.TestCase):
    def test_signed_instruction_binds_complete_request_and_human_trust(self):
        key = Ed25519PrivateKey.generate()
        instruction = contract.Instruction.from_dict(request())
        attestation = proof(key, "approve", request())
        assert verifier(key).verify("approve", instruction.to_dict(), attestation) == (
            "human:test",
            "approval-1",
        )
        with self.assertRaises(contract.ExecutionDenied):
            verifier(key).verify(
                "approve", replace(instruction, end=201).to_dict(), attestation
            )
        with self.assertRaises(contract.ExecutionDenied):
            verifier(Ed25519PrivateKey.generate()).verify(
                "approve", instruction.to_dict(), attestation
            )
        with self.assertRaises(contract.ExecutionDenied):
            verifier(key).verify("cancel", instruction.to_dict(), attestation)

    def test_public_schema_closes_instruction_and_approval(self):
        from pathlib import Path

        from jsonschema import Draft202012Validator

        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/execution/v1/instruction.schema.json"
            ).read_text()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(request())
        self.assertTrue(list(validator.iter_errors(request(human=True))))
        self.assertTrue(list(validator.iter_errors(request(interval=0))))
        self.assertTrue(list(validator.iter_errors(request(mode="manual"))))
        key = Ed25519PrivateKey.generate()
        attestation = proof(key, "approve", request())
        Draft202012Validator(schema["$defs"]["approval"]).validate(attestation)

    def test_closed_finite_contract(self):
        for changes in [
            {"end": None},
            {"end": 100},
            {"interval": 0},
            {"max_cycles": True},
            {"human": True},
            {"revision": 2},
            {"mode": "arrival"},
            {"max_cycle_seconds": -1},
            {"start": float("nan")},
            {"scope": [dict(channel="*", thread="t", tool="shell", action="review")]},
        ]:
            with (
                self.subTest(changes=changes),
                self.assertRaises(contract.ExecutionDenied),
            ):
                contract.Instruction.from_dict(request(**changes))
