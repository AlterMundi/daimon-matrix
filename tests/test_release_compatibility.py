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
    selected_artifacts,
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
    def test_credential_bound_selection_requires_its_actual_journal_reader(self):
        release = release_fixture()
        self.assertIn(
            "credential-bound-reader-validity/v1", release["contract"]["capabilities"]
        )
        self.assertEqual(
            release["contract"]["store_versions"]["reader_control"], [1, 2]
        )
        old = describe_reader()
        old["contract"]["store_versions"]["reader_control"] = [1]
        result = assess_reader(release, old, expected_digest=digest(release))
        self.assertFalse(result["compatible"])
        self.assertIn("store_versions_unsupported", result["reasons"])

    def test_distinct_receiver_code_keeps_shared_sdk_and_global_defaults(self):
        release = release_fixture()
        release["artifacts"]["owner_client"] = "6" * 64
        first = release["required_receivers"][0]
        first["artifacts"] = {"receiving_code": "7" * 64}
        second = {
            **first,
            "embodiment_id": "embodiment:synthetic2",
            "artifacts": {"receiving_code": "8" * 64},
        }
        release["required_receivers"].append(second)
        for row in (first, second):
            selected = selected_artifacts(
                release,
                being_ref=row["being_ref"],
                embodiment_id=row["embodiment_id"],
                expected_digest=digest(release),
            )
            self.assertEqual(selected["matrix_sdk"], release["artifacts"]["matrix_sdk"])
            self.assertEqual(selected["owner_client"], "6" * 64)
            self.assertEqual(
                selected["receiving_code"], row["artifacts"]["receiving_code"]
            )
            self.assertNotIn("telecodex", selected)
        selected.clear()
        self.assertEqual(second["artifacts"], {"receiving_code": "8" * 64})
        # Legacy rows still receive global selections without implicit upgrades.
        first.pop("artifacts")
        selected = selected_artifacts(
            release,
            being_ref=first["being_ref"],
            embodiment_id=first["embodiment_id"],
            expected_digest=digest(release),
        )
        self.assertEqual(selected, release["artifacts"])
        with self.assertRaisesRegex(
            ReleaseCompatibilityError, "release_receiver_missing"
        ):
            selected_artifacts(
                release,
                being_ref=first["being_ref"],
                embodiment_id="embodiment:unselected",
                expected_digest=digest(release),
            )

    def test_receiver_override_is_frozen_and_requires_declared_reader_support(self):
        release = release_fixture()
        release["required_receivers"][0]["artifacts"] = {"receiving_code": "7" * 64}
        approved = digest(release)
        altered = copy.deepcopy(release)
        altered["required_receivers"][0]["artifacts"]["receiving_code"] = "8" * 64
        with self.assertRaisesRegex(
            ReleaseCompatibilityError, "release_digest_mismatch"
        ):
            validate_release(altered, expected_digest=approved)
        old_reader = describe_reader()
        old_reader["contract"]["capabilities"].remove("per-receiver-artifacts/v1")
        result = assess_reader(release, old_reader, expected_digest=approved)
        self.assertFalse(result["compatible"])
        self.assertEqual(result["reasons"], ["capabilities_unsupported"])
        self.assertEqual(result["receiving_readiness"], "unobserved")
        release["contract"]["capabilities"].remove("per-receiver-artifacts/v1")
        with self.assertRaisesRegex(
            ReleaseCompatibilityError, "release_contract_invalid"
        ):
            validate_release(release, expected_digest=digest(release))

    def test_single_authority_group_requires_explicit_receiver_support(self):
        release = release_fixture()
        old = describe_reader()
        old["contract"]["capabilities"].remove("single-authority-group/v1")
        result = assess_reader(release, old, expected_digest=digest(release))
        self.assertFalse(result["compatible"])
        self.assertEqual(result["reasons"], ["capabilities_unsupported"])
        self.assertEqual(result["receiving_readiness"], "unobserved")

    def test_receiver_cannot_override_shared_sdk_or_reset_unselected_components(self):
        for artifacts in (
            {"matrix_sdk": "7" * 64},
            {"telecodex": None},
            {},
            {"custody": "7" * 64},
            {"receiving_code": "invalid"},
        ):
            release = release_fixture()
            release["required_receivers"][0]["artifacts"] = artifacts
            with (
                self.subTest(artifacts=artifacts),
                self.assertRaisesRegex(
                    ReleaseCompatibilityError, "release_contract_invalid"
                ),
            ):
                validate_release(release, expected_digest=digest(release))

    def test_old_reader_cannot_select_deferred_receipts_or_unfinished_intake(self):
        release = release_fixture()
        old = describe_reader()
        for capability in (
            "durable-group-intake/v1",
            "deferred-receipt-observation/v1",
        ):
            self.assertIn(capability, release["contract"]["capabilities"])
            old["contract"]["capabilities"].remove(capability)
        old["contract"]["pending_inspection"].remove(
            "dm.tribe.intake-reconciliation/v1"
        )
        result = assess_reader(release, old, expected_digest=digest(release))
        self.assertFalse(result["compatible"])
        self.assertIn("capabilities_unsupported", result["reasons"])
        self.assertEqual(result["receiving_readiness"], "unobserved")

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
