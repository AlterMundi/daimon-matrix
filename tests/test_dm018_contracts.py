#!/usr/bin/env python3
"""Independent DM-018 schema and cross-record conformance checks."""

import base64
import hashlib
import json
import os
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTOR_ROOT = os.path.join(ROOT, "vectors", "dm018")
SCHEMA_PATH = os.path.join(ROOT, "schemas", "adapters", "v0",
                           "contracts.schema.json")
INDEX_PATH = os.path.join(VECTOR_ROOT, "index.json")


class Reject(Exception):
    """A fixture violates a DM-018 cross-record invariant."""


def strict_load(path, require_canonical=True):
    with open(path, "rb") as stream:
        raw = stream.read()

    def reject_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise Reject("duplicate JSON property")
            value[key] = item
        return value

    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=reject_duplicates,
                           parse_float=lambda _: (_ for _ in ()).throw(
                               Reject("floating point is forbidden")),
                           parse_constant=lambda _: (_ for _ in ()).throw(
                               Reject("non-I-JSON constant")))
    except UnicodeDecodeError as error:
        raise Reject("invalid UTF-8") from error
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    if require_canonical and raw != canonical:
        raise Reject("fixture is not canonical JSON")
    return value


def assert_sorted_unique(values, name):
    if values != sorted(set(values)):
        raise Reject(f"{name} must be sorted and unique")


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def check_deployment_fence_crypto(record):
    descriptor = {
        "alg": "Ed25519",
        "public_key": record["issuer_public_key"],
    }
    expected_key_id = "dm:key:v0:" + base64.urlsafe_b64encode(
        hashlib.sha256(canonical_bytes(descriptor)).digest()
    ).rstrip(b"=").decode("ascii")
    if record["issuer_key_id"] != expected_key_id:
        raise Reject("deployment issuer key ID mismatch")
    body = {key: value for key, value in record.items()
            if key not in {"fence_id", "signature"}}
    preimage = b"daimon/deployment-fence/v0\x00" + canonical_bytes(body)
    digest = base64.urlsafe_b64encode(hashlib.sha256(preimage).digest()
                                     ).rstrip(b"=").decode("ascii")
    if record["fence_id"] != "dm:deployment-fence:v0:" + digest:
        raise Reject("deployment-fence content ID mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(
            b64url_decode(record["issuer_public_key"])
        ).verify(b64url_decode(record["signature"]), preimage)
    except (InvalidSignature, ValueError) as error:
        raise Reject("deployment-fence signature mismatch") from error


def check_manifest(record):
    if record.get("schema") != "daimon-adapter-manifest/v0":
        return
    assert_sorted_unique(record["capabilities"], "capabilities")
    contracts = [row["contract"] for row in record["contracts"]]
    assert_sorted_unique(contracts, "contracts")
    for row in record["contracts"]:
        assert_sorted_unique(row["versions"], "contract versions")


def check_migration(records):
    prior, candidate = records
    if candidate["migration_sequence"] != prior["migration_sequence"] + 1:
        raise Reject("migration sequence is not the exact successor")
    if candidate["predecessor_receipt_id"] != prior["receipt_id"]:
        raise Reject("migration predecessor mismatch")
    if candidate["outcome"] == "rolled-back" and \
            candidate["rollback_of_receipt_id"] != prior["receipt_id"]:
        raise Reject("rollback does not name the compensated receipt")
    for field, high_water in prior["covered_high_waters"].items():
        if candidate["covered_high_waters"][field] < high_water:
            raise Reject(f"covered high-water regressed: {field}")
    if candidate["covered_high_waters"]["migration_sequence"] != \
            candidate["migration_sequence"]:
        raise Reject("covered migration high-water mismatch")


def check_fence(records):
    prior, candidate = records
    if candidate["predecessor_fence_id"] != prior["fence_id"]:
        raise Reject("deployment-fence predecessor mismatch")
    old = (prior["generation"], prior["fencing_token"])
    new = (candidate["generation"], candidate["fencing_token"])
    if new[0] < old[0] or new[1] < old[1] or new == old:
        raise Reject("deployment-fence position did not advance")
    holder_changed = any(candidate[field] != prior[field] for field in (
        "holder", "realization_id", "volume_id"))
    if holder_changed and not (new[0] > old[0] and new[1] > old[1]):
        raise Reject("new realization/holder/volume needs a newer generation and token")


def check_dual_gate(record):
    if not record["delivery_accepted"]:
        return
    member_count = len(set(record["me_ids"]))
    if len(record["active_presence_ids"]) != member_count:
        raise Reject("delivery lacks exact active Matrix presence")
    if len(record["active_fence_ids"]) != member_count:
        raise Reject("delivery lacks exact active deployment fence")


def check_continuity(record):
    case = record["case"]
    identities = record["me_ids"]
    if case == "same-identity-relocation":
        if len(identities) != 2 or identities[0] != identities[1]:
            raise Reject("relocation must preserve the exact me_id")
        if len(record["active_presence_ids"]) != 1 or \
                len(record["active_fence_ids"]) != 1:
            raise Reject("relocation may expose only one active body")
    elif case == "distinct-identity-seeding":
        if len(identities) != 2 or len(set(identities)) != 2:
            raise Reject("seeding must create a distinct me_id")
        if record["event_cutoff"] != 0 or record["imported_personal_lanes"] != 0:
            raise Reject("seeded identity must start with empty personal lanes")
    elif case == "multi-member-we":
        if len(identities) < 2 or len(set(identities)) != len(identities):
            raise Reject("/we members must remain distinct identities")
        if len(record["active_presence_ids"]) != len(identities) or \
                len(record["active_fence_ids"]) != len(identities):
            raise Reject("each deployed /we member needs independent gates")
    else:
        raise Reject("continuity checker received the wrong scenario")


CHECKS = {
    "continuity-case": check_continuity,
    "dual-gate": check_dual_gate,
    "fence-monotonic": check_fence,
    "migration-monotonic": check_migration,
}


class DM018ContractsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = strict_load(SCHEMA_PATH, require_canonical=False)
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)
        cls.index = strict_load(INDEX_PATH)

    def records(self, entry):
        return [strict_load(os.path.join(VECTOR_ROOT, name))
                for name in entry["vectors"]]

    def test_index_is_closed_and_complete(self):
        self.assertEqual(self.index["schema"],
                         "dm-018-adapter-vector-index/v0")
        self.assertEqual(set(self.index),
                         {"entries", "json_schema", "schema", "spec"})
        ids = [entry["id"] for entry in self.index["entries"]]
        self.assertEqual(len(ids), len(set(ids)))
        indexed = {name for entry in self.index["entries"]
                   for name in entry["vectors"]}
        present = set()
        for directory in ("negative", "scenarios", "valid"):
            for name in os.listdir(os.path.join(VECTOR_ROOT, directory)):
                if name.endswith(".json"):
                    present.add(f"{directory}/{name}")
        self.assertEqual(indexed, present)

    def test_every_indexed_expectation(self):
        for entry in self.index["entries"]:
            with self.subTest(entry=entry["id"]):
                records = self.records(entry)
                errors = [list(self.validator.iter_errors(record))
                          for record in records]
                if entry["check"] == "schema":
                    rejected = any(error_set for error_set in errors)
                else:
                    self.assertFalse(any(errors), errors)
                    checker = CHECKS[entry["check"]]
                    try:
                        checker(records if len(records) > 1 else records[0])
                    except Reject:
                        rejected = True
                    else:
                        rejected = False
                self.assertEqual(rejected, entry["expect"] == "reject")

    def test_positive_manifests_are_deterministically_ordered(self):
        for entry in self.index["entries"]:
            if entry["expect"] != "accept":
                continue
            for record in self.records(entry):
                check_manifest(record)

    def test_deployment_fence_vectors_have_real_ids_and_signatures(self):
        paths = (
            "valid/deployment-fence-active.json",
            "negative/fence-regression.json",
        )
        for path in paths:
            with self.subTest(path=path):
                check_deployment_fence_crypto(
                    strict_load(os.path.join(VECTOR_ROOT, path)))

    def test_deployment_fence_crypto_rejects_tampering(self):
        record = strict_load(os.path.join(
            VECTOR_ROOT, "valid/deployment-fence-active.json"))
        modified_body = dict(record, fencing_token=record["fencing_token"] + 1)
        with self.assertRaises(Reject):
            check_deployment_fence_crypto(modified_body)
        modified_signature = dict(
            record, signature="A" + record["signature"][1:])
        with self.assertRaises(Reject):
            check_deployment_fence_crypto(modified_signature)

    def test_exact_version_negotiation_uses_local_preference(self):
        local = ["v2", "v0", "v1"]
        offered = ["v0"]
        selected = next((version for version in local if version in offered),
                        None)
        self.assertEqual(selected, "v0")
        self.assertIsNone(next((version for version in ["v1"]
                                if version in offered), None))

    def test_idempotency_key_cannot_name_different_bytes(self):
        first = {"idempotency_key": "A" * 43, "operation": "prepare"}
        replay = dict(first)
        conflict = dict(first, operation="commit")
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"))
        table = {first["idempotency_key"]: canonical(first)}
        self.assertEqual(table[replay["idempotency_key"]], canonical(replay))
        self.assertNotEqual(table[conflict["idempotency_key"]],
                            canonical(conflict))


if __name__ == "__main__":
    unittest.main()
