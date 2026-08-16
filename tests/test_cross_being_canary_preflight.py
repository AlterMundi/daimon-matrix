#!/usr/bin/env python3
"""Adversarial tests for the offline cross-being canary preflight freezer."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from daimon_matrix.canonical import canonical_bytes
from tools.build_cross_being_canary_preflight import (
    PLAN_SCHEMA,
    PreflightError,
    freeze_plan,
    main,
    validate_plan,
)

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/build_cross_being_canary_preflight.py"


def valid_plan() -> dict[str, Any]:
    components: dict[str, Any] = {}
    repositories = {
        "daimon-cluster": "https://github.com/nicoechaniz/daimon-cluster",
        "daimon-matrix": "https://github.com/AlterMundi/daimon-matrix",
        "tribe-bridge": "https://github.com/nicoechaniz/tribe-bridge",
    }
    for index, (name, repository) in enumerate(sorted(repositories.items()), start=1):
        components[name] = {
            "artifacts": [
                {
                    "name": f"{name}-rc.tar.gz",
                    "sha256": f"{index:064x}",
                    "size_bytes": index,
                }
            ],
            "commit": f"{index:040x}",
            "repository": repository,
            "tree": f"{index + 3:040x}",
        }

    def participant(marker: str) -> dict[str, Any]:
        return {
            "being_ref": f"dm:being:v1:{marker * 43}",
            "consent": {
                "evidence_ref": None,
                "inferred": False,
                "recorded": False,
                "required": True,
            },
            "custody": {
                "custodian_ref": f"opaque:custodian/{marker}",
                "independence_evidence_ref": None,
                "independence_verified": False,
                "must_be_independent": True,
                "store_ref": f"opaque:custody-store/{marker}",
            },
            "endpoint_ref": f"opaque:endpoint/{marker}",
            "participant_ref": f"opaque:participant/{marker}",
        }

    return {
        "components": components,
        "human_gates": {
            "custody_verification_complete": False,
            "exact_go_required": True,
            "execution_authorized": False,
            "external_contact_approved": False,
        },
        "limitations": {
            "offline_only": True,
            "performs_execution": False,
            "performs_network_io": False,
            "tribe_is_transitional_only": True,
        },
        "participants": {
            "side-a": participant("a"),
            "side-b": participant("b"),
        },
        "purpose": "cross-being-canary",
        "schema": PLAN_SCHEMA,
        "semantic_evidence": {
            "matrix_intake_observation_ref": "opaque:observation/matrix-intake",
            "matrix_intake_required": True,
            "matrix_receipt_observation_ref": "opaque:observation/matrix-receipt",
            "matrix_receipt_required": True,
            "tribe_ack_is_semantic": False,
            "tribe_ack_satisfies_matrix_intake": False,
            "tribe_ack_satisfies_matrix_receipt": False,
        },
        "steps": [
            {
                "action_ref": "opaque:procedure/deliver",
                "effect_refs": ["opaque:effect/message-offered"],
                "id": "deliver",
                "observation_refs": ["opaque:observation/matrix-intake"],
                "rollback": {
                    "action_ref": "opaque:procedure/revoke-delivery",
                    "effect_refs": ["opaque:effect/delivery-revoked"],
                    "observation_refs": ["opaque:observation/revocation-receipt"],
                },
            },
            {
                "action_ref": "opaque:procedure/observe-receipt",
                "effect_refs": ["opaque:effect/receipt-observed"],
                "id": "observe",
                "observation_refs": ["opaque:observation/matrix-receipt"],
                "rollback": {
                    "action_ref": "opaque:procedure/close-canary",
                    "effect_refs": ["opaque:effect/canary-closed"],
                    "observation_refs": ["opaque:observation/closure-receipt"],
                },
            },
        ],
        "transport": {
            "endpoint_resolution_allowed": False,
            "network_access_allowed": False,
            "transport_ref": "opaque:transport/candidate",
        },
    }


class CrossBeingCanaryValidationTests(unittest.TestCase):
    def test_closed_valid_plan(self) -> None:
        self.assertEqual(validate_plan(valid_plan()), valid_plan())

    def test_components_require_exact_pins_and_artifacts(self) -> None:
        mutations: list[tuple[list[str], Any]] = [
            (["components", "daimon-matrix", "commit"], "main"),
            (["components", "daimon-matrix", "commit"], "0" * 40),
            (["components", "daimon-matrix", "tree"], "f" * 39),
            (["components", "daimon-matrix", "repository"], "opaque:repo/matrix"),
            (
                ["components", "daimon-matrix", "artifacts", "0", "sha256"],
                "0" * 63,
            ),
            (
                ["components", "daimon-matrix", "artifacts", "0", "sha256"],
                "0" * 64,
            ),
            (
                ["components", "daimon-matrix", "artifacts", "0", "size_bytes"],
                0,
            ),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                plan = valid_plan()
                target: Any = plan
                for part in path[:-1]:
                    target = target[int(part)] if part.isdigit() else target[part]
                target[path[-1]] = replacement
                with self.assertRaises(PreflightError):
                    validate_plan(plan)

        plan = valid_plan()
        plan["components"]["daimon-matrix"]["artifacts"] *= 2
        with self.assertRaisesRegex(PreflightError, "artifacts_not_unique_sorted"):
            validate_plan(plan)

    def test_beings_and_all_independence_refs_must_differ(self) -> None:
        fields = [
            ("being_ref",),
            ("participant_ref",),
            ("endpoint_ref",),
            ("custody", "custodian_ref"),
            ("custody", "store_ref"),
        ]
        for path in fields:
            with self.subTest(path=path):
                plan = valid_plan()
                side_a: Any = plan["participants"]["side-a"]
                side_b: Any = plan["participants"]["side-b"]
                for part in path[:-1]:
                    side_a = side_a[part]
                    side_b = side_b[part]
                side_b[path[-1]] = side_a[path[-1]]
                with self.assertRaises(PreflightError):
                    validate_plan(plan)

        plan = valid_plan()
        plan["participants"]["side-b"]["custody"]["store_ref"] = plan["participants"][
            "side-a"
        ]["custody"]["custodian_ref"]
        with self.assertRaisesRegex(PreflightError, "all_custody_refs"):
            validate_plan(plan)

    def test_each_consent_gate_is_explicit_unrecorded_and_not_inferred(self) -> None:
        for side in ("side-a", "side-b"):
            for field, value in (
                ("required", False),
                ("recorded", True),
                ("inferred", True),
                ("evidence_ref", "opaque:consent/evidence"),
            ):
                with self.subTest(side=side, field=field):
                    plan = valid_plan()
                    plan["participants"][side]["consent"][field] = value
                    with self.assertRaises(PreflightError):
                        validate_plan(plan)

    def test_custody_is_required_but_cannot_be_claimed_verified(self) -> None:
        for side in ("side-a", "side-b"):
            for field, value in (
                ("must_be_independent", False),
                ("independence_verified", True),
                ("independence_evidence_ref", "opaque:custody/evidence"),
            ):
                with self.subTest(side=side, field=field):
                    plan = valid_plan()
                    plan["participants"][side]["custody"][field] = value
                    with self.assertRaises(PreflightError):
                        validate_plan(plan)

    def test_transport_is_opaque_and_offline(self) -> None:
        for hostile_ref in (
            "https://host.invalid",
            "opaque:endpoint/../host",
            "opaque:endpoint//host",
        ):
            plan = valid_plan()
            plan["participants"]["side-a"]["endpoint_ref"] = hostile_ref
            with (
                self.subTest(ref=hostile_ref),
                self.assertRaisesRegex(PreflightError, "invalid_endpoint_ref"),
            ):
                validate_plan(plan)
        for field in ("network_access_allowed", "endpoint_resolution_allowed"):
            plan = valid_plan()
            plan["transport"][field] = True
            with self.assertRaises(PreflightError):
                validate_plan(plan)

    def test_matrix_semantics_cannot_be_replaced_by_tribe_ack(self) -> None:
        for field in (
            "matrix_intake_required",
            "matrix_receipt_required",
            "tribe_ack_is_semantic",
            "tribe_ack_satisfies_matrix_intake",
            "tribe_ack_satisfies_matrix_receipt",
        ):
            plan = valid_plan()
            plan["semantic_evidence"][field] = not plan["semantic_evidence"][field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    PreflightError, "semantic_evidence_policy_mismatch"
                ),
            ):
                validate_plan(plan)

        plan = valid_plan()
        plan["semantic_evidence"]["matrix_receipt_observation_ref"] = (
            "opaque:observation/not-in-steps"
        )
        with self.assertRaisesRegex(PreflightError, "matrix_observations_missing"):
            validate_plan(plan)

        plan = valid_plan()
        plan["semantic_evidence"]["matrix_receipt_observation_ref"] = plan[
            "semantic_evidence"
        ]["matrix_intake_observation_ref"]
        with self.assertRaisesRegex(PreflightError, "matrix_observation_refs"):
            validate_plan(plan)

    def test_human_gates_and_limitations_cannot_be_opened(self) -> None:
        for field in (
            "custody_verification_complete",
            "execution_authorized",
            "external_contact_approved",
        ):
            plan = valid_plan()
            plan["human_gates"][field] = True
            with self.subTest(field=field), self.assertRaises(PreflightError):
                validate_plan(plan)
        plan = valid_plan()
        plan["human_gates"]["exact_go_required"] = False
        with self.assertRaises(PreflightError):
            validate_plan(plan)
        for field in ("performs_execution", "performs_network_io"):
            plan = valid_plan()
            plan["limitations"][field] = True
            with self.subTest(field=field), self.assertRaises(PreflightError):
                validate_plan(plan)

    def test_steps_are_declarative_closed_and_have_rollback(self) -> None:
        plan = valid_plan()
        plan["steps"][0]["argv"] = ["ssh", "host"]
        with self.assertRaisesRegex(PreflightError, "invalid_step_shape"):
            validate_plan(plan)

        for field in ("action_ref", "effect_refs", "observation_refs"):
            plan = valid_plan()
            del plan["steps"][0]["rollback"][field]
            with self.subTest(field=field), self.assertRaises(PreflightError):
                validate_plan(plan)

    def test_tool_has_no_execution_or_network_imports(self) -> None:
        tree = ast.parse(TOOL.read_text(encoding="utf-8"))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".")[0])
        self.assertTrue(
            {"subprocess", "socket", "urllib", "http", "asyncio"}.isdisjoint(imports)
        )


class CrossBeingCanaryFilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.input = self.root / "plan.json"
        self.output = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_plan(self, plan: dict[str, Any] | None = None) -> bytes:
        raw = canonical_bytes(plan or valid_plan()) + b"\n"
        self.input.write_bytes(raw)
        self.input.chmod(0o600)
        return raw

    def test_freeze_is_content_addressed_owner_only_and_non_authorizing(self) -> None:
        plan_bytes = self.write_plan()
        receipt = freeze_plan(self.input, self.output)
        digest = hashlib.sha256(plan_bytes).hexdigest()
        self.assertEqual(receipt["plan_sha256"], digest)
        self.assertEqual(receipt["required_go"], f"GO {digest}")
        self.assertIs(receipt["go_is_authorization"], False)
        self.assertIs(receipt["execution_authorized"], False)
        self.assertIs(receipt["external_contact_approved"], False)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(self.output.read_bytes(), canonical_bytes(receipt) + b"\n")

    def test_noncanonical_and_duplicate_json_are_rejected(self) -> None:
        self.input.write_text(json.dumps(valid_plan(), indent=2), encoding="utf-8")
        self.input.chmod(0o600)
        with self.assertRaisesRegex(PreflightError, "canonical"):
            freeze_plan(self.input, self.output)

        self.input.write_bytes(b'{"schema":"a","schema":"b"}\n')
        with self.assertRaisesRegex(PreflightError, "duplicate_json_key"):
            freeze_plan(self.input, self.output)

    def test_input_must_be_owner_only_regular_and_not_symlink(self) -> None:
        self.write_plan()
        self.input.chmod(0o640)
        with self.assertRaisesRegex(PreflightError, "owner_only"):
            freeze_plan(self.input, self.output)

        self.input.chmod(0o700)
        with self.assertRaisesRegex(PreflightError, "owner_only"):
            freeze_plan(self.input, self.output)

        self.input.unlink()
        target = self.root / "real-plan.json"
        target.write_bytes(canonical_bytes(valid_plan()) + b"\n")
        target.chmod(0o600)
        self.input.symlink_to(target)
        with self.assertRaisesRegex(PreflightError, "regular_file"):
            freeze_plan(self.input, self.output)

        self.input.unlink()
        os.link(target, self.input)
        with self.assertRaisesRegex(PreflightError, "regular_file"):
            freeze_plan(self.input, self.output)

    def test_input_and_output_parent_must_not_be_symlinks(self) -> None:
        real_parent = self.root / "real"
        real_parent.mkdir()
        linked_parent = self.root / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        input_path = linked_parent / "plan.json"
        real_input = real_parent / "plan.json"
        real_input.write_bytes(canonical_bytes(valid_plan()) + b"\n")
        real_input.chmod(0o600)
        with self.assertRaisesRegex(PreflightError, "plan_parent_must_be_real"):
            freeze_plan(input_path, self.output)

        self.write_plan()
        with self.assertRaisesRegex(PreflightError, "output_parent_must_be_real"):
            freeze_plan(self.input, linked_parent / "receipt.json")

    def test_output_is_no_overwrite_and_symlink_safe(self) -> None:
        self.write_plan()
        self.output.write_text("sentinel", encoding="utf-8")
        with self.assertRaisesRegex(PreflightError, "must_not_exist"):
            freeze_plan(self.input, self.output)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "sentinel")

        self.output.unlink()
        target = self.root / "target"
        target.write_text("sentinel", encoding="utf-8")
        self.output.symlink_to(target)
        with self.assertRaisesRegex(PreflightError, "must_not_exist"):
            freeze_plan(self.input, self.output)
        self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")

    def test_output_parent_must_be_owner_only(self) -> None:
        self.write_plan()
        self.root.chmod(0o755)
        with self.assertRaisesRegex(PreflightError, "output_parent_must_be_real"):
            freeze_plan(self.input, self.output)
        self.assertFalse(self.output.exists())

    def test_output_name_swap_during_sync_fails_without_deleting_replacement(
        self,
    ) -> None:
        self.write_plan()
        displaced = self.root / "displaced"
        replacement = b'{"execution_authorized":true}\n'
        real_fsync = os.fsync
        calls = 0

        def swapping_fsync(descriptor: int) -> None:
            nonlocal calls
            real_fsync(descriptor)
            calls += 1
            if calls == 1:
                self.output.rename(displaced)
                self.output.write_bytes(replacement)
                self.output.chmod(0o600)

        with (
            mock.patch(
                "tools.build_cross_being_canary_preflight.os.fsync",
                side_effect=swapping_fsync,
            ),
            self.assertRaisesRegex(PreflightError, "output_changed_during_write"),
        ):
            freeze_plan(self.input, self.output)
        self.assertEqual(self.output.read_bytes(), replacement)
        self.assertTrue(displaced.exists())

    def test_output_parent_swap_during_sync_fails(self) -> None:
        self.write_plan()
        output_parent = self.root / "output"
        output_parent.mkdir(mode=0o700)
        output = output_parent / "receipt.json"
        displaced = self.root / "displaced-output"
        real_fsync = os.fsync
        calls = 0

        def swapping_fsync(descriptor: int) -> None:
            nonlocal calls
            real_fsync(descriptor)
            calls += 1
            if calls == 1:
                output_parent.rename(displaced)
                output_parent.mkdir(mode=0o700)

        with (
            mock.patch(
                "tools.build_cross_being_canary_preflight.os.fsync",
                side_effect=swapping_fsync,
            ),
            self.assertRaisesRegex(
                PreflightError, "output_parent_changed_during_write"
            ),
        ):
            freeze_plan(self.input, output)
        self.assertFalse(output.exists())
        self.assertFalse((displaced / "receipt.json").exists())

    def test_cli_reports_success_and_does_not_overwrite(self) -> None:
        self.write_plan()
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "--input",
            os.fspath(self.input),
            "--output",
            os.fspath(self.output),
        ]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(main(arguments), 0)
            self.assertEqual(main(arguments), 1)
        self.assertIn('"execution_authorized": false', stdout.getvalue())
        self.assertEqual(stderr.getvalue().strip(), "output_must_not_exist")


if __name__ == "__main__":
    unittest.main()
