import copy
import hashlib
import json
import unittest
import uuid
from pathlib import Path

from jsonschema import Draft202012Validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import base64


ROOT = Path(__file__).resolve().parents[1]


def load_schema(name):
    return json.loads((ROOT / "schemas" / "weave" / "v1" / name).read_text())


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def ref(prefix):
    return f"{prefix}:{uuid.uuid4()}"


def manifest_value():
    first, second = ref("embodiment"), ref("embodiment")
    return {
        "schema": "being-manifest/v1",
        "being_ref": ref("being"),
        "revision": 1,
        "embodiments": sorted(
            [
                {"embodiment_id": first, "principal_id": "compaii@legion", "body_ref": "cluster:legion:compaii", "status": "active"},
                {"embodiment_id": second, "principal_id": "compaii@daimonmatrix", "body_ref": "cluster:daimonmatrix:compaii", "status": "active"},
            ],
            key=lambda row: row["embodiment_id"],
        ),
    }


def event_value(manifest):
    manifest_hash = hashlib.sha256(canonical(manifest)).hexdigest()
    core = {
        "protocol": "dm.we.v1", "event_id": str(uuid.uuid4()),
        "being_ref": manifest["being_ref"], "manifest_hash": manifest_hash,
        "origin": {
            "embodiment_id": manifest["embodiments"][0]["embodiment_id"],
            "incarnation_id": ref("incarnation"),
            "principal_id": manifest["embodiments"][0]["principal_id"],
            "body_ref": manifest["embodiments"][0]["body_ref"],
        },
        "sequence": 1, "previous_event_id": None, "occurred_at_ms": 1,
        "causal_parents": [], "kind": "configuration.proposed",
        "subject": "github.identity", "payload": {"email": "compaii@legion", "secret_slot_ref": "github/legion"},
        "supersedes": None, "sensitivity": "private",
    }
    return {
        **core, "content_hash": hashlib.sha256(canonical(core)).hexdigest(),
        "signature": {"alg": "Ed25519", "kid": "compaii/sig/1", "value": "A" * 86},
    }


class WeaveV1ContractsTest(unittest.TestCase):
    def test_manifest_and_event_match_public_schemas(self):
        manifest = manifest_value()
        Draft202012Validator(load_schema("being-manifest.schema.json")).validate(manifest)
        Draft202012Validator(load_schema("event.schema.json")).validate(event_value(manifest))

    def test_schema_rejects_wrong_model_and_open_fields(self):
        mutations = [
        lambda event: event.update(protocol="dm.experimental"),
        lambda event: event.update(kind="presence.singleton"),
        lambda event: event["origin"].update(embodiment_id="invalid"),
        lambda event: event.update(extra="authority escalation"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                manifest = manifest_value()
                event = event_value(manifest)
                mutate(event)
                errors = list(Draft202012Validator(load_schema("event.schema.json")).iter_errors(event))
                self.assertTrue(errors)

    def test_manifest_hash_changes_for_membership_revision(self):
        manifest = manifest_value()
        before = hashlib.sha256(canonical(manifest)).hexdigest()
        changed = copy.deepcopy(manifest)
        changed["revision"] += 1
        after = hashlib.sha256(canonical(changed)).hexdigest()
        self.assertNotEqual(before, after)

    def test_published_vector_is_canonical_and_signature_valid(self):
        root = ROOT / "vectors" / "weave" / "v1"
        index = json.loads((root / "index.json").read_text())
        manifest_raw = (root / index["manifest"]).read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual(manifest_raw, canonical(manifest) + b"\n")
        self.assertEqual(hashlib.sha256(canonical(manifest)).hexdigest(), index["manifest_hash"])
        event_raw = (root / index["valid_events"][0]).read_bytes()
        event = json.loads(event_raw)
        self.assertEqual(event_raw, canonical(event) + b"\n")
        core = {key: value for key, value in event.items() if key not in {"content_hash", "signature"}}
        digest = hashlib.sha256(canonical(core)).hexdigest()
        self.assertEqual(digest, event["content_hash"])
        public = index["public_keys"][event["signature"]["kid"]]
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        Ed25519PublicKey.from_public_bytes(decode(public)).verify(
            decode(event["signature"]["value"]),
            b"daimon/weave/event/v1\x00" + bytes.fromhex(digest),
        )
