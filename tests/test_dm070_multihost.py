from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.multihost import (
    MultihostEvidenceError,
    create_multihost_receipt,
    validate_cluster_provenance,
    validate_multihost_receipt,
)
from daimon_matrix.synthetic_multihost import (
    SyntheticMultihostError,
    run_synthetic_multihost,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "conformance/fixtures/dm070-multihost.json"
PROVENANCE = ROOT / "provenance/daimon-cluster-v1.json"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise AssertionError(f"expected object: {path}")
    return value


def core(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key not in {"receipt_hash", "receipt_id"}
    }


class DM070InstalledJourneyTests(unittest.TestCase):
    provenance: dict[str, Any]
    fixture: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.provenance = load(PROVENANCE)
        cls.fixture = load(FIXTURE)

    @unittest.skip("historical pre-RC runtime fixture; production requires V7")
    def test_two_installed_processes_reproduce_exact_closed_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm070-test-") as temporary:
            receipt = run_synthetic_multihost(
                Path(temporary),
                source_commit="0" * 40,
                cluster_provenance=self.provenance,
            )
            self.assertEqual(canonical_bytes(receipt), canonical_bytes(self.fixture))
            self.assertNotIn(os.fspath(temporary), canonical_bytes(receipt).decode())
        self.assertEqual(validate_multihost_receipt(receipt), receipt)
        self.assertEqual(
            receipt["receipt_id"],
            "dm:multihost-receipt:v1:dbuhl6lSXvDyhvgdblFznURaXIa5coLVi5pPCCdFH64",
        )
        self.assertEqual(receipt["sync"]["event_count"], 9)
        self.assertEqual(
            [row["new_lane_sequence"] for row in [receipt["succession"]]], [1]
        )
        self.assertEqual(
            (
                receipt["adoption"]["legion_state"],
                receipt["adoption"]["daimonmatrix_state"],
            ),
            ("reverted", "rejected"),
        )

    def test_receipt_semantic_substitutions_fail_before_rehash(self) -> None:
        cases: list[tuple[str, Any]] = []

        changed = core(self.fixture)
        changed["authority"]["successor_manifest_hash"] = changed["authority"][
            "initial_manifest_hash"
        ]
        cases.append(("authority epoch collapsed", changed))

        changed = core(self.fixture)
        changed["authority"]["embodiments"][1]["capability_id"] = changed["authority"][
            "embodiments"
        ][0]["capability_id"]
        cases.append(("capability aliased", changed))

        changed = core(self.fixture)
        changed["processes"]["restart_count"] = 2
        cases.append(("durable boundaries skipped", changed))

        changed = core(self.fixture)
        changed["partition"]["opposite_ledgers_unaware"] = False
        cases.append(("partition awareness fabricated", changed))

        changed = core(self.fixture)
        changed["sync"]["directions"].reverse()
        cases.append(("direction relabelled", changed))

        changed = core(self.fixture)
        changed["sync"]["interruptions"].reverse()
        cases.append(("durable boundary reordered", changed))

        changed = core(self.fixture)
        changed["adoption"]["daimonmatrix_state"] = "reverted"
        cases.append(("observer result collapsed", changed))

        changed = core(self.fixture)
        changed["succession"]["old_write_error"] = "accepted"
        cases.append(("old incarnation accepted", changed))

        changed = core(self.fixture)
        changed["cluster"]["different_resource"] = "fence_not_current"
        cases.append(("independent resource suppressed", changed))

        changed = core(self.fixture)
        changed["historical"]["event_authority"] = True
        cases.append(("historical receipt promoted", changed))

        changed = core(self.fixture)
        changed["isolation"]["no_winner_election"] = False
        cases.append(("winner elected", changed))

        changed = core(self.fixture)
        changed["schedule"][3], changed["schedule"][4] = (
            changed["schedule"][4],
            changed["schedule"][3],
        )
        cases.append(("schedule reordered", changed))

        for name, changed in cases:
            with self.subTest(name=name), self.assertRaises(MultihostEvidenceError):
                create_multihost_receipt(changed)

    def test_closed_evidence_rejects_tamper_leak_and_winner_metadata(self) -> None:
        changed = copy.deepcopy(self.fixture)
        changed["receipt_hash"] = "0" * 64
        with self.assertRaisesRegex(
            MultihostEvidenceError, "multihost_receipt_hash_mismatch"
        ):
            validate_multihost_receipt(changed)

        for field, value in (
            ("arrival_order_winner", "legion"),
            ("host_path", "/private/runtime"),
            ("fallback_transport", "tribe-v1"),
        ):
            changed = copy.deepcopy(self.fixture)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(MultihostEvidenceError):
                validate_multihost_receipt(changed)

        with tempfile.TemporaryDirectory(prefix="dm070-not-empty-") as temporary:
            (Path(temporary) / "owned").write_bytes(b"preserve")
            with self.assertRaisesRegex(
                SyntheticMultihostError, "synthetic_root_not_empty"
            ):
                run_synthetic_multihost(
                    Path(temporary),
                    source_commit="0" * 40,
                    cluster_provenance=self.provenance,
                )
            self.assertEqual((Path(temporary) / "owned").read_bytes(), b"preserve")


class DM070PublishedContractTests(unittest.TestCase):
    def test_schema_vectors_index_and_generator_are_exact(self) -> None:
        schema = load(ROOT / "schemas/multihost/v1/receipt.schema.json")
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        vector_root = ROOT / "vectors/multihost/v1"
        valid = load(vector_root / "valid/receipt.json")
        validator.validate(valid)
        self.assertEqual(validate_multihost_receipt(valid), valid)
        self.assertEqual(canonical_bytes(valid), canonical_bytes(load(FIXTURE)))

        for path in sorted((vector_root / "negative").glob("*.json")):
            with (
                self.subTest(path=path.name),
                self.assertRaises(MultihostEvidenceError),
            ):
                validate_multihost_receipt(load(path))

        index = load(vector_root / "index.json")
        self.assertEqual(index["schema"], "dm.multihost.vector-index/v1")
        for item in index["files"]:
            self.assertEqual(
                hashlib.sha256((vector_root / item["name"]).read_bytes()).hexdigest(),
                item["sha256"],
            )
        # The checked-in vectors are historical pre-RC evidence. Their V3
        # process generator is deliberately not an RC qualification gate.

    def test_cluster_provenance_is_bounded_and_fail_closed(self) -> None:
        provenance = load(PROVENANCE)
        self.assertEqual(validate_cluster_provenance(provenance), provenance)
        changed = copy.deepcopy(provenance)
        changed["authority_limits"]["fence_authority"] = True
        with self.assertRaisesRegex(
            MultihostEvidenceError, "cluster_provenance_claims_authority"
        ):
            validate_cluster_provenance(changed)
        changed = copy.deepcopy(provenance)
        changed["historical_canary"]["receipt_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            MultihostEvidenceError, "cluster_provenance_hash_mismatch"
        ):
            validate_cluster_provenance(changed)

    def test_cluster_checkout_matches_exact_pins(self) -> None:
        provenance = load(PROVENANCE)
        configured = os.environ.get("DAIMON_DM070_CLUSTER_ROOT")
        sibling = Path(configured) if configured else ROOT.parent / "daimon-cluster"
        if not (sibling / ".git").exists():
            self.skipTest("pinned daimon-cluster checkout is not present")
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=sibling,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(commit, provenance["commit"])
        pins = (
            (
                provenance["hosting_contract"]["contract_path"],
                provenance["hosting_contract"]["contract_sha256"],
            ),
            (
                provenance["hosting_contract"]["process_test_path"],
                provenance["hosting_contract"]["process_test_sha256"],
            ),
            (
                provenance["historical_canary"]["receipt_path"],
                provenance["historical_canary"]["receipt_sha256"],
            ),
        )
        for relative, expected in pins:
            self.assertEqual(
                hashlib.sha256((sibling / relative).read_bytes()).hexdigest(), expected
            )


if __name__ == "__main__":
    unittest.main()
