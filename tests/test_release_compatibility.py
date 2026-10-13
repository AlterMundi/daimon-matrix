"""Receiving contract comparison cannot manufacture adoption or activation."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import unittest

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.release_compatibility import (
    RELEASE_SCHEMA,
    ReleaseCompatibilityError,
    assess_reader,
    describe_reader,
    validate_release,
)


def release_fixture():
    closure = [
        {
            "being_ref": "dm:being:v1:synthetic",
            "control_head": "dm:control:v1:synthetic",
            "manifest_hash": "1" * 64,
        }
    ]
    return {
        "schema": RELEASE_SCHEMA,
        "artifacts": {"matrix_sdk": "2" * 64},
        "provenance": {"matrix_revision": "3" * 40, "qualification_sha256": "4" * 64},
        "contract": describe_reader()["contract"],
        "authorities": {"current": closure, "candidate": copy.deepcopy(closure)},
        "required_receivers": [
            {
                "being_ref": closure[0]["being_ref"],
                "embodiment_id": "embodiment:synthetic",
                "expected_selection_sha256": "5" * 64,
            }
        ],
    }


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


class ReleaseCompatibilityTests(unittest.TestCase):
    def test_compatible_code_is_not_loaded_readiness(self):
        release = release_fixture()
        result = assess_reader(
            release, describe_reader(), expected_digest=digest(release)
        )
        self.assertTrue(result["compatible"])
        self.assertEqual(result["receiving_readiness"], "unobserved")
        self.assertEqual(result["reasons"], [])
        self.assertNotIn("selected", result)
        self.assertNotIn("adopted", result)
        checked = validate_release(release, expected_digest=digest(release))
        checked["required_receivers"].clear()
        self.assertEqual(len(release["required_receivers"]), 1)

    def test_approved_manifest_cannot_drop_receiver_or_change_artifact(self):
        release = release_fixture()
        approved = digest(release)
        for field in ("artifacts", "required_receivers", "authorities", "contract"):
            modified = copy.deepcopy(release)
            if field == "artifacts":
                modified[field]["matrix_sdk"] = "a" * 64
            elif field == "required_receivers":
                modified[field].append(
                    {
                        **modified[field][0],
                        "embodiment_id": "embodiment:other",
                    }
                )
            elif field == "authorities":
                modified[field]["candidate"][0]["manifest_hash"] = "a" * 64
            else:
                modified[field]["capabilities"].append("unsupported/v1")
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    ReleaseCompatibilityError, "release_digest_mismatch"
                ),
            ):
                validate_release(modified, expected_digest=approved)

    def test_unsupported_read_write_store_and_capabilities_fail_closed(self):
        for field, value in (
            ("wire_read", "dm.future-input/v1"),
            ("wire_write", "dm.future-output/v1"),
            ("capabilities", "member-directed/v1"),
            ("pending_inspection", "dm.future-delivery/v1"),
        ):
            release = release_fixture()
            release["contract"][field] = sorted(release["contract"][field] + [value])
            result = assess_reader(
                release, describe_reader(), expected_digest=digest(release)
            )
            self.assertFalse(result["compatible"])
            self.assertEqual(result["reasons"], [field + "_unsupported"])
        release = release_fixture()
        release["contract"]["store_versions"]["communication"] = [5]
        result = assess_reader(
            release, describe_reader(), expected_digest=digest(release)
        )
        self.assertFalse(result["compatible"])
        self.assertEqual(result["reasons"], ["store_versions_unsupported"])

    def test_interpreter_and_profile_are_not_guessed_from_package_version(self):
        for field in ("interpreter", "profile"):
            release = release_fixture()
            release["contract"][field] = (
                {"implementation": "future-python", "version": [3, 13, 5]}
                if field == "interpreter"
                else "member-directed/v1"
            )
            result = assess_reader(
                release, describe_reader(), expected_digest=digest(release)
            )
            self.assertFalse(result["compatible"])
            self.assertEqual(result["reasons"], [field + "_unsupported"])

    def test_reader_description_is_not_a_mutable_global(self):
        reader = describe_reader()
        reader["contract"]["capabilities"].append("member-directed/v1")
        self.assertNotIn(
            "member-directed/v1", describe_reader()["contract"]["capabilities"]
        )

    def test_closed_bounded_data_rejects_duplicates_booleans_and_private_fields(self):
        release = release_fixture()
        variants = []
        x = copy.deepcopy(release)
        x["required_receivers"] *= 2
        variants.append(x)
        x = copy.deepcopy(release)
        x["authorities"]["candidate"] *= 2
        variants.append(x)
        x = copy.deepcopy(release)
        x["contract"]["store_versions"]["communication"] = [True]
        variants.append(x)
        x = copy.deepcopy(release)
        x["contract"]["pending_transmission"] = "renew-expiry"
        variants.append(x)
        x = copy.deepcopy(release)
        x["provider_token"] = "not-a-real-secret"
        variants.append(x)
        x = copy.deepcopy(release)
        x["artifacts"]["custody"] = "a" * 64
        variants.append(x)
        for index, variant in enumerate(variants):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(
                    ReleaseCompatibilityError, "release_contract_invalid"
                ),
            ):
                validate_release(variant, expected_digest=digest(variant))

    def test_module_probe_needs_no_runtime_or_private_binding(self):
        result = subprocess.run(
            [sys.executable, "-m", "daimon_matrix.release_compatibility"],
            capture_output=True,
            check=True,
            text=True,
        )
        self.assertEqual(json.loads(result.stdout), describe_reader())
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
