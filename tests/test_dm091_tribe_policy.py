"""The tribe channel's policy shape, and why it cannot carry a grant.

`specs/tribe-conversation.md` §2 is explicit that conversation authority is
membership: a tribe message never requires a resource or operation grant and never
creates one. The pairwise channel is the opposite -- its policy *requires* a grant
(`grant_refs` carries `minItems: 1`) and pins one peer, one relationship and one
resource.

So a tribe channel is not the pairwise policy with a longer member list. These tests
pin the second shape and, more importantly, pin that it stays closed: a
configuration supplying `grant_refs`, `resource_ref`, `operation` or any `peer_*`
field is rejected rather than carried into an envelope. An empty field that a later
change could populate is the opening this closes.

The application fixture here is built by hand instead of reusing the runtime
fixture because this test is on the CI mypy list and that one is not; importing it
would drag sixty-odd pre-existing typing errors into this file's check.
"""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from typing import Any

from daimon_matrix.messaging import MessagingTribePolicy
from daimon_matrix.messaging_config import (
    APPLICATION_JSON_SCHEMA,
    SPECIFICATION_SCHEMA,
    MessagingConfigError,
    validate_shape,
)

TRIBE_REF = "dm:tribe:v1:" + "A" * 43
MEMBERSHIP_REF = "dm:membership:v1:" + "B" * 43
HOST = "127.0.0.1"
PORT = 8000
STORES = {
    "relationships": "relationships.sqlite3",
    "inbox": "inbox.sqlite3",
    "outgoing-context": "outgoing-context.sqlite3",
    "outbox": "outbox.sqlite3",
    "opaque-evidence": "opaque-evidence.sqlite3",
    "opaque-message": "opaque-message.sqlite3",
}


def _route(direction: str, phase: str) -> dict[str, Any]:
    # Incoming routes must point at this host's own listener; outgoing routes only
    # need a well-formed http(s) endpoint with the exact phase path.
    host = HOST if direction == "incoming" else "203.0.113.7"
    return {
        "provider_ref": f"{direction}-{phase}-provider",
        "route_ref": f"{direction}-{phase}-route",
        "key_ref": f"{direction}-{phase}-key",
        "endpoint": f"http://{host}:{PORT}/dm-messaging/v1/{phase}",
        "secret_file": f"{direction}-{phase}.key",
        "secret_sha256": "0" * 64,
    }


def _direction(channel_id: str) -> dict[str, Any]:
    return {
        "channel_id": channel_id,
        "recipient_being_ref": "dm:being:v1:" + "C" * 43,
        "recipient_credential_id": "dm:credential:v1:" + "D" * 43,
        "policy": {
            "peer_being_ref": "dm:being:v1:" + "C" * 43,
            "peer_embodiment_id": "embodiment:" + "e" * 36,
            "peer_credential_id": "dm:credential:v1:" + "D" * 43,
            "relationship_id": "dm:relationship:v1:" + "E" * 43,
            "tribe_ref": TRIBE_REF,
            "membership_ref": MEMBERSHIP_REF,
            "resource_ref": "cluster:resource:messaging",
            "operation": "messaging.read",
            "classification": "shareable",
            "max_ttl_ms": 60_000,
            "grant_refs": [
                {
                    "grant_id": "dm:grant:v1:" + "F" * 43,
                    "event_id": "dm:event:v1:" + "a" * 43,
                    "event_hash": "1" * 64,
                }
            ],
        },
        "routes": {
            "evidence": _route(channel_id, "evidence"),
            "message": _route(channel_id, "message"),
        },
    }


def _spec() -> dict[str, Any]:
    """A minimal valid specification: pairwise lane only, no tribe section."""

    return {
        "schema": "dm.messaging.application/v1",
        "listen": {"host": HOST, "port": PORT},
        "authorities": [{}, {}],
        "relationship_events": [{}],
        "incoming": _direction("incoming"),
        "outgoing": _direction("outgoing"),
        "stores": dict(STORES),
    }


def _tribe(channel_id: str = "tribe-main") -> dict[str, Any]:
    return {
        "channel_id": channel_id,
        "policy": {
            "tribe_ref": TRIBE_REF,
            "membership_ref": MEMBERSHIP_REF,
            "classification": "shareable",
            "max_ttl_ms": 60_000,
        },
    }


class TribePolicyShapeTests(unittest.TestCase):
    def test_the_policy_names_membership_and_nothing_else(self) -> None:
        self.assertEqual(
            {"tribe_ref", "membership_ref", "classification", "max_ttl_ms"},
            {field.name for field in fields(MessagingTribePolicy)},
        )

    def test_the_pairwise_authority_fields_are_absent_not_empty(self) -> None:
        names = {field.name for field in fields(MessagingTribePolicy)}
        for forbidden in (
            "peer_being_ref",
            "peer_embodiment_id",
            "peer_credential_id",
            "relationship_id",
            "resource_ref",
            "operation",
            "grant_refs",
        ):
            self.assertNotIn(forbidden, names)

    def test_the_policy_is_immutable(self) -> None:
        policy = MessagingTribePolicy(
            tribe_ref=TRIBE_REF,
            membership_ref=MEMBERSHIP_REF,
            classification="shareable",
        )
        with self.assertRaises(FrozenInstanceError):
            policy.tribe_ref = "dm:tribe:v1:" + "C" * 43  # type: ignore[misc]


class TribeChannelConfigurationTests(unittest.TestCase):
    def test_the_fixture_is_valid_before_anything_is_added(self) -> None:
        """Guards every rejection test below: without this they prove nothing."""

        validate_shape(_spec(), specification=True)

    def test_an_application_without_a_tribe_section_still_validates(self) -> None:
        self.assertNotIn("tribe", _spec())
        self.assertNotIn("tribe", SPECIFICATION_SCHEMA["required"])
        self.assertNotIn("tribe", APPLICATION_JSON_SCHEMA["required"])

    def test_a_valid_tribe_section_validates(self) -> None:
        spec = _spec()
        spec["tribe"] = _tribe()
        validate_shape(spec, specification=True)

    def test_a_grant_in_a_tribe_policy_is_rejected(self) -> None:
        spec = _spec()
        spec["tribe"] = _tribe()
        spec["tribe"]["policy"]["grant_refs"] = [
            {
                "grant_id": "dm:grant:v1:" + "F" * 43,
                "event_id": "dm:event:v1:" + "a" * 43,
                "event_hash": "1" * 64,
            }
        ]
        with self.assertRaises(MessagingConfigError):
            validate_shape(spec, specification=True)

    def test_pairwise_authority_fields_in_a_tribe_policy_are_rejected(self) -> None:
        for forbidden, value in (
            ("resource_ref", "cluster:resource:messaging"),
            ("operation", "messaging.read"),
            ("peer_being_ref", "dm:being:v1:" + "C" * 43),
            ("peer_embodiment_id", "embodiment:" + "e" * 36),
            ("peer_credential_id", "dm:credential:v1:" + "D" * 43),
            ("relationship_id", "dm:relationship:v1:" + "E" * 43),
        ):
            with self.subTest(field=forbidden):
                spec = _spec()
                spec["tribe"] = _tribe()
                spec["tribe"]["policy"][forbidden] = value
                with self.assertRaises(MessagingConfigError):
                    validate_shape(spec, specification=True)

    def test_an_incomplete_tribe_policy_is_rejected(self) -> None:
        for missing in ("tribe_ref", "membership_ref", "classification", "max_ttl_ms"):
            with self.subTest(missing=missing):
                spec = _spec()
                section = _tribe()
                del section["policy"][missing]
                spec["tribe"] = section
                with self.assertRaises(MessagingConfigError):
                    validate_shape(spec, specification=True)

    def test_an_unknown_classification_is_rejected(self) -> None:
        spec = _spec()
        spec["tribe"] = _tribe()
        spec["tribe"]["policy"]["classification"] = "tribe-public-everything"
        with self.assertRaises(MessagingConfigError):
            validate_shape(spec, specification=True)

    def test_an_unknown_tribe_section_field_is_rejected(self) -> None:
        spec = _spec()
        spec["tribe"] = _tribe()
        spec["tribe"]["recipients"] = ["dm:being:v1:" + "C" * 43]
        with self.assertRaises(MessagingConfigError):
            validate_shape(spec, specification=True)

    def test_a_tribe_channel_may_not_reuse_a_pairwise_channel_id(self) -> None:
        """One channel id means one channel; the surface must stay unambiguous."""

        for direction in ("incoming", "outgoing"):
            with self.subTest(direction=direction):
                spec = _spec()
                spec["tribe"] = _tribe(copy.deepcopy(spec[direction]["channel_id"]))
                with self.assertRaises(MessagingConfigError):
                    validate_shape(spec, specification=True)

    def test_a_distinct_tribe_channel_id_is_accepted(self) -> None:
        spec = _spec()
        spec["tribe"] = _tribe("tribe-other")
        validate_shape(spec, specification=True)


class PublishedSchemaTests(unittest.TestCase):
    def test_the_tribe_section_is_optional_and_closed_in_both_versions(self) -> None:
        root = Path(__file__).resolve().parents[1] / "schemas" / "messaging"
        for version in ("v1", "v2"):
            with self.subTest(version=version):
                schema = json.loads(
                    (root / version / "application.schema.json").read_bytes()
                )
                self.assertIn("tribe", schema["properties"])
                self.assertNotIn("tribe", schema["required"])
                self.assertFalse(schema["additionalProperties"])
                section = schema["properties"]["tribe"]
                self.assertFalse(section["additionalProperties"])
                self.assertEqual({"channel_id", "policy"}, set(section["properties"]))
                policy = section["properties"]["policy"]
                self.assertFalse(policy["additionalProperties"])
                self.assertEqual(
                    {
                        "tribe_ref",
                        "membership_ref",
                        "classification",
                        "max_ttl_ms",
                    },
                    set(policy["properties"]),
                )
                self.assertEqual(
                    sorted(policy["properties"]), sorted(policy["required"])
                )

    def test_published_v1_still_equals_the_python_schema(self) -> None:
        root = Path(__file__).resolve().parents[1] / "schemas" / "messaging"
        published = json.loads((root / "v1" / "application.schema.json").read_bytes())
        self.assertEqual(APPLICATION_JSON_SCHEMA, published)


if __name__ == "__main__":
    unittest.main()
