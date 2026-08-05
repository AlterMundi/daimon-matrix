from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import wasmtime
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    ValidationError,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.local_api import create_request
from daimon_matrix.runtime import RuntimeError as HostedRuntimeError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.species import (
    APPLICATION_EVENT_KIND,
    CompatibilityVerifier,
    SpeciesCAS,
    SpeciesError,
    SpeciesRegistry,
    _bundle_manifest,
    create_species_genesis,
    create_species_release,
    derive_species_id,
    maintainer_policy,
    maintainer_policy_from_seeds,
    validate_content_ref,
    validate_release_body,
)
from daimon_matrix.species_runner import DeterministicWasiRunner, SpeciesRunnerError
from daimon_matrix.synthetic_species import main as synthetic_species_main
from daimon_matrix.synthetic_species import run_synthetic_species
from tests.test_dm022_ledger import NOW
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture


def h(value: Any) -> str:
    return b64url(hashlib.sha256(canonical_bytes(value)).digest())


class SpeciesFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.cas = SpeciesCAS(root / "cas.sqlite3")
        self.registry = SpeciesRegistry(root / "registry.sqlite3", self.cas)
        self.seeds = [bytes(range(1, 33)), bytes(range(33, 65))]
        self.policy = maintainer_policy_from_seeds(self.seeds, 2)
        self.resource_profile = {
            "aggregate_cpu_fuel": 200_000,
            "aggregate_wall_timeout_ms": 2_000,
            "case_count": 8,
            "clock": "fixed-zero",
            "cpu_fuel": 100_000,
            "environment": [],
            "execution_model": "wasm32-wasi-preview1-deterministic/v0",
            "file_count": 8,
            "filesystem_bytes": 4096,
            "memory_bytes": 1_048_576,
            "network": "denied",
            "process_count": 1,
            "randomness": "denied",
            "schema": "species-resource-profile/v0",
            "stderr_bytes": 1024,
            "stdout_bytes": 1024,
            "thread_count": 1,
            "wall_timeout_ms": 1_000,
        }
        self.resource_ref = self.put_json(
            self.resource_profile,
            "application/vnd.daimon.species-resource-profile.v0+json",
        )
        semantics = {
            "execution_model": "wasm32-wasi-preview1-deterministic/v0",
            "schema": "species-wasi-semantics/v0",
        }
        semantics_ref = self.put_json(
            semantics, "application/vnd.daimon.species-wasi-semantics.v0+json"
        )
        conformance_ref = self.put_json(
            {
                "runner_version": "wasmtime-python/45.0.0-dm061.1",
                "schema": "species-runner-conformance/v0",
                "verdict": "pass",
            },
            "application/vnd.daimon.species-runner-conformance.v0+json",
        )
        runner_ref = self.put_json(
            {
                "resource_profile_ref": self.resource_ref,
                "result_encoding": "daimon-test-result-jcs/v0",
                "runner_conformance_ref": conformance_ref,
                "runner_version": "wasmtime-python/45.0.0-dm061.1",
                "schema": "species-runner-profile/v0",
                "wasi_semantics_ref": semantics_ref,
            },
            "application/vnd.daimon.species-runner-profile.v0+json",
        )
        self.runner_ref = runner_ref
        module = bytes(
            wasmtime.wat2wasm(
                '(module (func (export "verify")) (func (export "invariant")))'
            )
        )
        module_ref = self.cas.put(module, "application/wasm")
        input_ref = self.cas.put(b"", "application/octet-stream")
        self.input_ref = input_ref
        expected_ref = self.put_json(
            {
                "case_id": "case.pass",
                "exit_code": 0,
                "schema": "daimon-test-result-jcs/v0",
                "stderr_base64": "",
                "stdout_base64": "",
            },
            "application/vnd.daimon.daimon-test-result-jcs.v0+json",
        )
        case = {
            "case_id": "case.pass",
            "entrypoint_id": "verify",
            "expected_result_ref": expected_ref,
            "input_ref": input_ref,
        }
        suite_ref = self.put_json(
            {
                "cases": [case],
                "runner_profile_ref": runner_ref,
                "schema": "species-suite-manifest/v0",
                "suite_id": "suite.core",
                "suite_version": "1",
            },
            "application/vnd.daimon.species-suite-manifest.v0+json",
        )
        invariant_case = {**case, "entrypoint_id": "invariant"}
        invariant_ref = self.put_json(
            {
                "cases": [invariant_case],
                "definition_ref": self.cas.put(
                    b"identity/history authority remains immutable",
                    "text/plain",
                ),
                "invariant_id": "invariant.identity-history",
                "invariant_version": "1",
                "runner_profile_ref": runner_ref,
                "schema": "species-invariant-manifest/v0",
            },
            "application/vnd.daimon.species-invariant-manifest.v0+json",
        )
        self.invariant_ref = invariant_ref
        self.bundle_ref = self.put_json(
            {
                "dependencies": [],
                "entrypoints": [
                    {"entrypoint_id": "invariant", "export_name": "invariant"},
                    {"entrypoint_id": "verify", "export_name": "verify"},
                ],
                "files": [],
                "module": module_ref,
                "schema": "species-implementation-bundle/v0",
            },
            "application/vnd.daimon.species-implementation-bundle.v0+json",
        )
        contract_ref = self.put_json(
            {"contract": "core", "schema": "synthetic-contract/v0"},
            "application/vnd.daimon.synthetic-contract.v0+json",
        )
        requirement_ref = self.put_json(
            {"requirement": "deterministic", "schema": "synthetic-requirement/v0"},
            "application/vnd.daimon.synthetic-requirement.v0+json",
        )
        bounds_ref = self.put_json(
            {"bound": "closed", "schema": "synthetic-bounds/v0"},
            "application/vnd.daimon.synthetic-bounds.v0+json",
        )
        root_ref = self.put_json(
            {
                "ontology": "being-to-embodiment-to-incarnation",
                "schema": "synthetic-root-me-definition/v0",
            },
            "application/vnd.daimon.synthetic-root-me-definition.v0+json",
        )
        suite = {
            "suite_id": "suite.core",
            "suite_ref": suite_ref,
            "suite_version": "1",
        }
        invariant = {
            "invariant_id": "invariant.identity-history",
            "invariant_ref": invariant_ref,
            "invariant_version": "1",
        }
        self.genome = {
            "capability_contracts": [
                {
                    "contract_id": "contract.core",
                    "contract_ref": contract_ref,
                    "version": "1",
                }
            ],
            "compatibility_requirements": {
                "forbidden_authority_changes": ["invariant.identity-history"],
                "required_contract_ids": ["contract.core"],
                "required_invariants": [invariant],
                "required_suites": [suite],
                "resource_profile": self.resource_ref,
            },
            "conformance_suites": [suite],
            "implementation_invariants": [invariant],
            "protocol_requirements": [
                {
                    "bounds_ref": bounds_ref,
                    "requirement_id": "protocol.core",
                    "requirement_ref": requirement_ref,
                    "version": "1",
                }
            ],
            "root_me_definition": root_ref,
        }
        self.core = {
            "cryptographic_suite": (
                "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"
            ),
            "domain_version": 0,
            "genome": self.genome,
            "initial_maintainers": self.policy,
            "maintainer_floor": {
                "minimum_key_count": 2,
                "minimum_threshold": 2,
            },
            "origin": {
                "branch_foundation": None,
                "kind": "primordial",
                "parent_branch_release": None,
            },
            "protocol_version": 0,
            "species_nonce": b64url(bytes(range(65, 97))),
        }
        self.species_id = derive_species_id(self.core)

    def branch_material(
        self, parent_release: Mapping[str, Any]
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        list[bytes],
    ]:
        child_module = bytes(
            wasmtime.wat2wasm(
                """(module
                  (func (export "verify") unreachable)
                  (func (export "invariant")))"""
            )
        )
        child_module_ref = self.cas.put(child_module, "application/wasm")
        child_bundle_ref = self.put_json(
            {
                "dependencies": [],
                "entrypoints": [
                    {"entrypoint_id": "invariant", "export_name": "invariant"},
                    {"entrypoint_id": "verify", "export_name": "verify"},
                ],
                "files": [],
                "module": child_module_ref,
                "schema": "species-implementation-bundle/v0",
            },
            "application/vnd.daimon.species-implementation-bundle.v0+json",
        )
        child_expected_ref = self.put_json(
            {
                "case_id": "case.pass",
                "exit_code": 1,
                "schema": "daimon-test-result-jcs/v0",
                "stderr_base64": "",
                "stdout_base64": "",
            },
            "application/vnd.daimon.daimon-test-result-jcs.v0+json",
        )
        child_suite_ref = self.put_json(
            {
                "cases": [
                    {
                        "case_id": "case.pass",
                        "entrypoint_id": "verify",
                        "expected_result_ref": child_expected_ref,
                        "input_ref": self.input_ref,
                    }
                ],
                "runner_profile_ref": self.runner_ref,
                "schema": "species-suite-manifest/v0",
                "suite_id": "suite.core",
                "suite_version": "1",
            },
            "application/vnd.daimon.species-suite-manifest.v0+json",
        )
        child_genome: dict[str, Any] = copy.deepcopy(self.genome)
        child_suite = {
            "suite_id": "suite.core",
            "suite_ref": child_suite_ref,
            "suite_version": "1",
        }
        child_genome["conformance_suites"] = [child_suite]
        child_genome["compatibility_requirements"]["required_suites"] = [child_suite]
        verifier = CompatibilityVerifier(self.cas)
        breaking_delta = verifier.build_breaking_delta(
            parent_genome=self.genome,
            child_genome=child_genome,
        )
        incompatibility_report = verifier.build_branch_report(
            parent_genome=self.genome,
            child_genome=child_genome,
            child_implementation_bundle=child_bundle_ref,
            breaking_delta=breaking_delta,
        )
        child_seeds = [bytes(range(66, 98)), bytes(range(98, 130))]
        child_policy = maintainer_policy_from_seeds(child_seeds, 2)
        foundation = {
            "branch_nonce": b64url(bytes(range(130, 162))),
            "breaking_delta": breaking_delta,
            "child_genome": child_genome,
            "child_implementation_bundle": child_bundle_ref,
            "child_initial_maintainers": child_policy,
            "child_maintainer_floor": {
                "minimum_key_count": 2,
                "minimum_threshold": 2,
            },
            "child_species_nonce": b64url(bytes(range(162, 194))),
            "incompatibility_report": incompatibility_report,
            "parent_base_release": {
                "artifact_hash": parent_release["artifact_hash"],
                "artifact_id": parent_release["artifact_id"],
                "epoch": parent_release["body"]["position"]["epoch"],
                "sequence": parent_release["body"]["position"]["sequence"],
                "species_id": self.species_id,
            },
            "parent_species_id": self.species_id,
            "schema": "daimon-species-branch-foundation/v0",
        }
        base = {
            **parent_release["body"],
            "artifact_hash": parent_release["artifact_hash"],
            "artifact_id": parent_release["artifact_id"],
        }
        parent_report = verifier.build_report(
            candidate_genome=self.genome,
            implementation_bundle=self.bundle_ref,
            base_release=base,
        )
        parent_position = parent_release["body"]["position"]
        declaration_body = {
            **parent_release["body"],
            "branch_declaration": foundation,
            "compatibility_report": parent_report,
            "issued_at_ms": 10,
            "position": {
                "epoch": parent_position["epoch"],
                "sequence": parent_position["sequence"] + 1,
            },
            "previous_release": {
                "artifact_hash": parent_release["artifact_hash"],
                "artifact_id": parent_release["artifact_id"],
                "epoch": parent_position["epoch"],
                "sequence": parent_position["sequence"],
            },
            "release_kind": "branch-declaration",
            "release_label": "synthetic-child-declaration",
        }
        declaration = create_species_release(declaration_body, self.seeds)
        child_core = {
            **self.core,
            "genome": child_genome,
            "initial_maintainers": child_policy,
            "maintainer_floor": foundation["child_maintainer_floor"],
            "origin": {
                "branch_foundation": foundation,
                "kind": "branch",
                "parent_branch_release": {
                    "artifact_hash": declaration["artifact_hash"],
                    "artifact_id": declaration["artifact_id"],
                    "epoch": declaration_body["position"]["epoch"],
                    "sequence": declaration_body["position"]["sequence"],
                },
            },
            "species_nonce": foundation["child_species_nonce"],
        }
        child_genesis = create_species_genesis(
            child_core, child_seeds, child_seeds, created_at_ms=11
        )
        child_species_id = derive_species_id(child_core)
        child_report = verifier.build_report(
            candidate_genome=child_genome,
            implementation_bundle=child_bundle_ref,
            base_release=None,
        )
        child_release = create_species_release(
            {
                "authorizing_policy_hash": h(child_policy),
                "branch_declaration": None,
                "compatibility_report": child_report,
                "fork_resolution": None,
                "genesis": {
                    "artifact_hash": child_genesis["artifact_hash"],
                    "artifact_id": child_genesis["artifact_id"],
                },
                "genome": child_genome,
                "implementation_bundle": child_bundle_ref,
                "issued_at_ms": 12,
                "next_maintainers": child_policy,
                "position": {"epoch": 0, "sequence": 0},
                "previous_release": None,
                "release_kind": "genesis",
                "release_label": "synthetic-child-0",
                "schema": "daimon-species-release/v0",
                "species_id": child_species_id,
            },
            child_seeds,
        )
        return declaration, child_genesis, child_release, foundation, child_seeds

    def put_json(self, value: Any, media_type: str) -> dict[str, Any]:
        return self.cas.put(canonical_bytes(value), media_type)

    def genesis(
        self,
        *,
        authorizers: list[bytes] | None = None,
        possessors: list[bytes] | None = None,
    ) -> dict[str, Any]:
        return create_species_genesis(
            self.core,
            self.seeds if authorizers is None else authorizers,
            self.seeds if possessors is None else possessors,
            created_at_ms=1,
        )

    def release_zero(self, genesis: dict[str, Any]) -> dict[str, Any]:
        report = CompatibilityVerifier(self.cas).build_report(
            candidate_genome=self.genome,
            implementation_bundle=self.bundle_ref,
            base_release=None,
        )
        body = {
            "authorizing_policy_hash": h(self.policy),
            "branch_declaration": None,
            "compatibility_report": report,
            "fork_resolution": None,
            "genesis": {
                "artifact_hash": genesis["artifact_hash"],
                "artifact_id": genesis["artifact_id"],
            },
            "genome": self.genome,
            "implementation_bundle": self.bundle_ref,
            "issued_at_ms": 2,
            "next_maintainers": self.policy,
            "position": {"epoch": 0, "sequence": 0},
            "previous_release": None,
            "release_kind": "genesis",
            "release_label": "synthetic-0",
            "schema": "daimon-species-release/v0",
            "species_id": self.species_id,
        }
        return create_species_release(body, self.seeds)

    def successor(
        self, genesis: dict[str, Any], predecessor: dict[str, Any], *, label: str
    ) -> dict[str, Any]:
        base = {
            **predecessor["body"],
            "artifact_hash": predecessor["artifact_hash"],
            "artifact_id": predecessor["artifact_id"],
        }
        report = CompatibilityVerifier(self.cas).build_report(
            candidate_genome=self.genome,
            implementation_bundle=self.bundle_ref,
            base_release=base,
        )
        position = predecessor["body"]["position"]
        body = {
            "authorizing_policy_hash": h(predecessor["body"]["next_maintainers"]),
            "branch_declaration": None,
            "compatibility_report": report,
            "fork_resolution": None,
            "genesis": {
                "artifact_hash": genesis["artifact_hash"],
                "artifact_id": genesis["artifact_id"],
            },
            "genome": self.genome,
            "implementation_bundle": self.bundle_ref,
            "issued_at_ms": 3,
            "next_maintainers": self.policy,
            "position": {
                "epoch": position["epoch"],
                "sequence": position["sequence"] + 1,
            },
            "previous_release": {
                "artifact_hash": predecessor["artifact_hash"],
                "artifact_id": predecessor["artifact_id"],
                "epoch": position["epoch"],
                "sequence": position["sequence"],
            },
            "release_kind": "compatible",
            "release_label": label,
            "schema": "daimon-species-release/v0",
            "species_id": self.species_id,
        }
        return create_species_release(body, self.seeds)

    def fork_resolution(
        self,
        genesis: Mapping[str, Any],
        common: Mapping[str, Any],
        heads: list[Mapping[str, Any]],
        *,
        authorizers: list[bytes] | None = None,
        possessors: list[bytes] | None = None,
    ) -> dict[str, Any]:
        entries = []
        for head in heads:
            position = head["body"]["position"]
            entries.append(
                {
                    "artifact_hash": head["artifact_hash"],
                    "artifact_id": head["artifact_id"],
                    "epoch": position["epoch"],
                    "previous_release": head["body"]["previous_release"],
                    "sequence": position["sequence"],
                }
            )
        entries.sort(
            key=lambda item: (item["epoch"], item["sequence"], item["artifact_id"])
        )
        page = {
            "entries": entries,
            "page_index": 0,
            "schema": "species-fork-closure-page/v0",
        }
        page_ref = self.put_json(
            page,
            "application/vnd.daimon.species-fork-closure-page.v0+json",
        )
        common_position = common["body"]["position"]
        common_ref = {
            "artifact_hash": common["artifact_hash"],
            "artifact_id": common["artifact_id"],
            "epoch": common_position["epoch"],
            "sequence": common_position["sequence"],
        }
        root = {
            "common_predecessor": common_ref,
            "epoch": entries[0]["epoch"],
            "occupied_count": len(entries),
            "pages": [
                {
                    "entry_count": len(entries),
                    "first_key": {
                        "artifact_id": entries[0]["artifact_id"],
                        "epoch": entries[0]["epoch"],
                        "sequence": entries[0]["sequence"],
                    },
                    "last_key": {
                        "artifact_id": entries[-1]["artifact_id"],
                        "epoch": entries[-1]["epoch"],
                        "sequence": entries[-1]["sequence"],
                    },
                    "page_index": 0,
                    "page_ref": page_ref,
                }
            ],
            "schema": "species-fork-closure-root/v0",
            "species_id": self.species_id,
        }
        root_ref = self.put_json(
            root,
            "application/vnd.daimon.species-fork-closure-root.v0+json",
        )
        base = {
            **common["body"],
            "artifact_hash": common["artifact_hash"],
            "artifact_id": common["artifact_id"],
        }
        report = CompatibilityVerifier(self.cas).build_report(
            candidate_genome=self.genome,
            implementation_bundle=self.bundle_ref,
            base_release=base,
        )
        body = {
            "authorizing_policy_hash": h(common["body"]["next_maintainers"]),
            "branch_declaration": None,
            "compatibility_report": report,
            "fork_resolution": {
                "closed_epoch": entries[0]["epoch"],
                "closure_cursor": {
                    "epoch": entries[0]["epoch"],
                    "max_sequence": max(item["sequence"] for item in entries),
                    "occupied_count": len(entries),
                    "occupied_manifest_ref": root_ref,
                },
                "common_predecessor": common_ref,
                "competing_heads": [
                    {
                        "artifact_hash": item["artifact_hash"],
                        "artifact_id": item["artifact_id"],
                        "epoch": item["epoch"],
                        "sequence": item["sequence"],
                    }
                    for item in entries
                ],
            },
            "genesis": {
                "artifact_hash": genesis["artifact_hash"],
                "artifact_id": genesis["artifact_id"],
            },
            "genome": self.genome,
            "implementation_bundle": self.bundle_ref,
            "issued_at_ms": 20,
            "next_maintainers": self.policy,
            "position": {"epoch": entries[0]["epoch"] + 1, "sequence": 0},
            "previous_release": common_ref,
            "release_kind": "fork-resolution",
            "release_label": "synthetic-fork-resolution",
            "schema": "daimon-species-release/v0",
            "species_id": self.species_id,
        }
        return create_species_release(
            body,
            self.seeds if authorizers is None else authorizers,
            self.seeds if possessors is None else possessors,
        )


class DM061SpeciesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dm061-test-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.fixture = SpeciesFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def activate_lineage(self) -> tuple[dict[str, Any], dict[str, Any]]:
        genesis = self.fixture.genesis()
        self.assertEqual(
            self.fixture.registry.ingest_genesis(genesis)["state"], "active"
        )
        release = self.fixture.release_zero(genesis)
        self.assertEqual(
            self.fixture.registry.ingest_release(release)["state"], "accepted"
        )
        return genesis, release

    def test_section14_registry_is_exact_closed_and_executable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        registry_path = root / "conformance/species-section14-v0.json"
        registry = json.loads(registry_path.read_bytes())
        schema = json.loads(
            (root / "schemas/species/v0/scenario-registry.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(registry)
        section = (root / "specs/species-evolution.md").read_text(encoding="utf-8")
        section = section.split("## 14. Required positive and negative scenarios\n", 1)[
            1
        ].split("\n## 15. Downstream contracts", 1)[0]
        rows = []
        for line in section.splitlines():
            if line.startswith("| ") and not line.startswith("| Scenario "):
                columns = [column.strip() for column in line.strip("|").split("|")]
                if len(columns) == 2 and columns != ["---", "---"]:
                    rows.append(columns)
        self.assertEqual(len(rows), 124)
        self.assertEqual(
            [(case["scenario"], case["required_result"]) for case in registry["cases"]],
            [tuple(row) for row in rows],
        )
        from daimon_matrix.conformance import _test_exists

        for case in registry["cases"]:
            _test_exists(case["evidence"], root)

    def test_artifact_validation_negative_matrix(self) -> None:
        genesis = self.fixture.genesis()
        release = self.fixture.release_zero(genesis)
        wrapper_mutations = []
        unknown = copy.deepcopy(genesis)
        unknown["locator"] = "https://invalid.example/species"
        wrapper_mutations.append(unknown)
        wrong_id = copy.deepcopy(genesis)
        replacement = "B" if genesis["artifact_id"].endswith("A") else "A"
        wrong_id["artifact_id"] = genesis["artifact_id"][:-1] + replacement
        wrapper_mutations.append(wrong_id)
        wrong_role = copy.deepcopy(genesis)
        wrong_role["signatures"][0]["role"] = "species-release-authorization"
        wrapper_mutations.append(wrong_role)
        duplicate_signature = copy.deepcopy(genesis)
        duplicate_signature["signatures"].append(
            copy.deepcopy(duplicate_signature["signatures"][0])
        )
        wrapper_mutations.append(duplicate_signature)
        for mutation in wrapper_mutations:
            with (
                self.subTest(kind="wrapper", mutation=mutation),
                self.assertRaises(SpeciesError),
            ):
                self.fixture.registry.ingest_genesis(mutation)

        for invalid in (True, -1, 2**53):
            body = copy.deepcopy(release["body"])
            body["position"]["sequence"] = invalid
            with self.subTest(position=invalid), self.assertRaises(SpeciesError):
                validate_release_body(body)

        content = copy.deepcopy(self.fixture.bundle_ref)
        content["locator"] = "file:///ambient/secret"
        with self.assertRaisesRegex(SpeciesError, "content_ref_fields"):
            validate_content_ref(content)

        aliased = copy.deepcopy(self.fixture.policy)
        aliased["keys"][1] = copy.deepcopy(aliased["keys"][0])
        invalid_policies = [
            {**self.fixture.policy, "threshold": 0},
            {**self.fixture.policy, "threshold": 3},
            aliased,
            {
                **self.fixture.policy,
                "keys": list(reversed(self.fixture.policy["keys"])),
            },
        ]
        for policy in invalid_policies:
            with self.subTest(policy=policy), self.assertRaises(SpeciesError):
                maintainer_policy(policy)

    def test_registry_authority_negative_matrix(self) -> None:
        genesis, release = self.activate_lineage()
        normal = self.fixture.successor(genesis, release, label="normal")
        gap_body = copy.deepcopy(normal["body"])
        gap_body["position"]["sequence"] += 1
        gap = create_species_release(gap_body, self.fixture.seeds)
        with self.assertRaisesRegex(SpeciesError, "release_position_gap"):
            self.fixture.registry.ingest_release(gap)

        wrong_previous_body = copy.deepcopy(normal["body"])
        other_hash = b64url(hashlib.sha256(b"other").digest())
        wrong_previous_body["previous_release"]["artifact_hash"] = other_hash
        wrong_previous_body["previous_release"]["artifact_id"] = (
            "dm:species-release:v0:" + other_hash
        )
        wrong_previous = create_species_release(wrong_previous_body, self.fixture.seeds)
        with self.assertRaises(SpeciesError):
            self.fixture.registry.ingest_release(wrong_previous)

        new_seeds = [
            hashlib.sha256(b"rotation-a").digest(),
            hashlib.sha256(b"rotation-b").digest(),
        ]
        new_policy = maintainer_policy_from_seeds(new_seeds, 2)
        rotation_body = copy.deepcopy(normal["body"])
        rotation_body["next_maintainers"] = new_policy
        rotation = create_species_release(rotation_body, self.fixture.seeds, new_seeds)
        self.assertEqual(
            self.fixture.registry.ingest_release(rotation)["state"], "accepted"
        )
        retired = self.fixture.successor(genesis, rotation, label="retired-policy")
        with self.assertRaises(SpeciesError):
            self.fixture.registry.ingest_release(retired)

        below_floor = maintainer_policy_from_seeds([hashlib.sha256(b"one").digest()], 1)
        base = self.fixture.successor(genesis, rotation, label="below-floor")
        below_body = copy.deepcopy(base["body"])
        below_body["next_maintainers"] = below_floor
        below = create_species_release(
            below_body, new_seeds, [hashlib.sha256(b"one").digest()]
        )
        with self.assertRaisesRegex(SpeciesError, "maintainer_policy_below_floor"):
            self.fixture.registry.ingest_release(below)

    def test_compatibility_sandbox_negative_matrix(self) -> None:
        runner = DeterministicWasiRunner()
        for imported in ("path_create_directory", "sock_accept", "random_get"):
            module = bytes(
                wasmtime.wat2wasm(
                    f'''(module
                      (import "wasi_snapshot_preview1" "{imported}"
                        (func $forbidden (param i32 i32) (result i32)))
                      (func (export "run")))'''
                )
            )
            with (
                self.subTest(imported=imported),
                self.assertRaisesRegex(SpeciesRunnerError, "runner_forbidden_import"),
            ):
                runner.run(
                    case_id=imported,
                    module_bytes=module,
                    export_name="run",
                    input_bytes=b"",
                    bundle_files={},
                    dependency_files={},
                    resource_profile=self.fixture.resource_profile,
                )

        invalid_bundle = {
            "dependencies": [],
            "entrypoints": [{"entrypoint_id": "run", "export_name": "run"}],
            "files": [
                {
                    "content": self.fixture.input_ref,
                    "mode": "read-only",
                    "path": "../escape",
                }
            ],
            "module": self.fixture.cas.put(
                bytes(wasmtime.wat2wasm('(module (func (export "run")))')),
                "application/wasm",
            ),
            "schema": "species-implementation-bundle/v0",
        }
        invalid_ref = self.fixture.put_json(
            invalid_bundle,
            "application/vnd.daimon.species-implementation-bundle.v0+json",
        )
        with self.assertRaisesRegex(SpeciesError, "bundle_file_path"):
            _bundle_manifest(self.fixture.cas, invalid_ref)

        module_ref = invalid_bundle["module"]
        dependency: dict[str, Any] | None = None
        for _index in range(34):
            dependency = self.fixture.put_json(
                {
                    "dependencies": [] if dependency is None else [dependency],
                    "entrypoints": [{"entrypoint_id": "run", "export_name": "run"}],
                    "files": [],
                    "module": module_ref,
                    "schema": "species-implementation-bundle/v0",
                },
                "application/vnd.daimon.species-implementation-bundle.v0+json",
            )
        assert dependency is not None
        with self.assertRaisesRegex(SpeciesError, "bundle_dependency_depth"):
            _bundle_manifest(self.fixture.cas, dependency)

    def test_application_projection_negative_matrix(self) -> None:
        _genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(
            hashlib.sha256(b"application-negative").digest()
        )
        veto = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": False,
                "policy_version": "veto",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=veto,
        )
        self.assertFalse(snapshot["snapshot_core"]["application_eligible"])
        self.assertIn("local-veto", snapshot["snapshot_core"]["reason_codes"])
        pointer = self.root / "negative.pointer"
        with self.assertRaises(SpeciesError):
            self.fixture.registry.apply(
                operation_id="99999999-9999-4999-8999-999999999999",
                snapshot=snapshot,
                local_policy_ref=veto,
                capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
                pointer_path=pointer,
                applied_at_ms=60,
                append_event=lambda payload: payload,
            )
        self.assertFalse(pointer.exists())
        tampered = copy.deepcopy(snapshot)
        tampered["snapshot_core"]["subject_me_id"] = "dm:being:v1:" + b64url(
            hashlib.sha256(b"other-subject").digest()
        )
        with self.assertRaises(SpeciesError):
            self.fixture.registry.apply(
                operation_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                snapshot=tampered,
                local_policy_ref=veto,
                capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
                pointer_path=pointer,
                applied_at_ms=61,
                append_event=lambda payload: payload,
            )
        self.assertFalse(pointer.exists())

    def test_branch_birth_negative_matrix(self) -> None:
        _genesis, parent_release = self.activate_lineage()
        declaration, child_genesis, child_release, foundation, child_seeds = (
            self.fixture.branch_material(parent_release)
        )
        self.assertEqual(
            self.fixture.registry.ingest_release(declaration)["state"], "accepted"
        )
        changed_core = copy.deepcopy(child_genesis["body"]["genesis_core"])
        changed_core["origin"]["branch_foundation"] = copy.deepcopy(foundation)
        changed_core["origin"]["branch_foundation"]["branch_nonce"] = b64url(
            hashlib.sha256(b"different-foundation").digest()
        )
        mismatched = create_species_genesis(
            changed_core, child_seeds, child_seeds, created_at_ms=13
        )
        with self.assertRaises(SpeciesError):
            self.fixture.registry.ingest_genesis(mismatched)
        self.assertEqual(
            self.fixture.registry.birth_context(child_release["artifact_id"])["state"],
            "context-incomplete",
        )
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/species/v0/synthetic.schema.json"
            ).read_bytes()
        )
        root = self.root / "negative-claims"
        root.mkdir(mode=0o700)
        report = run_synthetic_species(root)
        report["synthetic"] = False
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(report)

    def test_published_species_schema_accepts_closed_canonical_contracts(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas/species/v0/contracts.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        genesis = self.fixture.genesis()
        release = self.fixture.release_zero(genesis)
        validator.validate(genesis)
        validator.validate(release)
        self.fixture.registry.ingest_genesis(genesis)
        self.fixture.registry.ingest_release(release)
        incoming = self.fixture.registry.incoming(
            subject_me_id=(
                "dm:being:v1:" + b64url(hashlib.sha256(b"schema-subject").digest())
            ),
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
        )
        validator.validate(incoming)
        policy = {
            "allowed_species": [self.fixture.species_id],
            "auto_apply": True,
            "policy_version": "schema-test",
            "resource_profile_ref": self.fixture.resource_ref,
            "schema": "daimon-species-local-application-policy/v0",
        }
        validator.validate(policy)

        left = self.fixture.successor(genesis, release, label="schema-left")
        right = self.fixture.successor(genesis, release, label="schema-right")
        resolution = self.fixture.fork_resolution(genesis, release, [left, right])
        validator.validate(left)
        validator.validate(right)
        validator.validate(resolution)
        declaration, child_genesis, child_release, foundation, _child_seeds = (
            self.fixture.branch_material(release)
        )
        validator.validate(foundation)
        validator.validate(declaration)
        validator.validate(child_genesis)
        validator.validate(child_release)

    def test_runner_provenance_and_generated_vector_index_are_exact(self) -> None:
        root = Path(__file__).resolve().parents[1]
        requirement = (root / "requirements-species.txt").read_text(encoding="utf-8")
        provenance = json.loads((root / "provenance/wasi-runner-v0.json").read_bytes())
        self.assertEqual(provenance["schema"], "dm.species-runner-provenance/v0")
        self.assertEqual(provenance["version"], "45.0.0")
        self.assertEqual(
            provenance["distribution"]["filename"],
            "wasmtime-45.0.0-py3-none-manylinux1_x86_64.whl",
        )
        digest = provenance["distribution"]["sha256"]
        self.assertEqual(len(digest), 64)
        self.assertIn("wasmtime==45.0.0", requirement)
        self.assertIn(f"--hash=sha256:{digest}", requirement)

        vector_root = root / "vectors/species/v0"
        index = json.loads((vector_root / "index.json").read_bytes())
        report = json.loads((vector_root / index["report"]).read_bytes())
        registry = json.loads(
            (root / "conformance/species-section14-v0.json").read_bytes()
        )
        self.assertEqual(
            index["report_sha256"], hashlib.sha256(canonical_bytes(report)).hexdigest()
        )
        self.assertEqual(
            index["scenario_registry_sha256"],
            hashlib.sha256(canonical_bytes(registry)).hexdigest(),
        )
        self.assertEqual(
            index["claims"],
            {
                "agent_zero": False,
                "first_real_speciation": False,
                "live_deployment": False,
                "synthetic": True,
            },
        )

    def test_synthetic_species_report_is_reproducible_closed_and_secret_free(
        self,
    ) -> None:
        reports = []
        for name in ("synthetic-a", "synthetic-b"):
            root = self.root / name
            root.mkdir(mode=0o700)
            reports.append(run_synthetic_species(root))
        self.assertEqual(canonical_bytes(reports[0]), canonical_bytes(reports[1]))
        fixture_path = (
            Path(__file__).resolve().parents[1]
            / "conformance/fixtures/dm061-synthetic-species.json"
        )
        self.assertEqual(reports[0], json.loads(fixture_path.read_bytes()))
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas/species/v0/synthetic.schema.json"
        )
        schema = json.loads(schema_path.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(reports[0])
        raw = canonical_bytes(reports[0])
        for forbidden in (
            b"PRIVATE KEY",
            b"OPENAI_API_KEY",
            b"ANTHROPIC_API_KEY",
            str(self.root).encode(),
        ):
            self.assertNotIn(forbidden, raw)

    def test_synthetic_species_entrypoint_rejects_nonempty_state_and_writes_atomic(
        self,
    ) -> None:
        state = self.root / "entrypoint-state"
        state.mkdir(mode=0o700)
        output = self.root / "report.json"
        self.assertEqual(
            synthetic_species_main(
                ["--state-root", str(state), "--output", str(output)]
            ),
            0,
        )
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/species/v0/synthetic.schema.json"
            ).read_bytes()
        )
        Draft202012Validator(schema).validate(json.loads(output.read_bytes()))
        nonempty = self.root / "nonempty-state"
        nonempty.mkdir(mode=0o700)
        (nonempty / "unrelated").touch()
        self.assertEqual(
            synthetic_species_main(["--state-root", str(nonempty)]),
            2,
        )

    def test_genesis_partial_endorsements_merge_without_fork(self) -> None:
        first = self.fixture.genesis(
            authorizers=[self.fixture.seeds[0]],
            possessors=[self.fixture.seeds[0]],
        )
        second = self.fixture.genesis(
            authorizers=[self.fixture.seeds[1]],
            possessors=[self.fixture.seeds[1]],
        )
        self.assertEqual(
            self.fixture.registry.ingest_genesis(first)["state"], "pending"
        )
        self.assertEqual(
            self.fixture.registry.ingest_genesis(second)["state"], "active"
        )

    def test_genesis_release_and_compatible_successor_replay(self) -> None:
        genesis, release = self.activate_lineage()
        self.assertEqual(
            self.fixture.registry.ingest_release(release)["state"], "accepted"
        )
        successor = self.fixture.successor(genesis, release, label="synthetic-1")
        self.assertEqual(
            self.fixture.registry.ingest_release(successor)["state"], "accepted"
        )
        self.assertEqual(
            self.fixture.registry.release(successor["artifact_id"]).artifact_id,
            successor["artifact_id"],
        )

    def test_same_position_siblings_quarantine_without_hash_winner(self) -> None:
        genesis, release = self.activate_lineage()
        first = self.fixture.successor(genesis, release, label="left")
        second = self.fixture.successor(genesis, release, label="right")
        self.assertEqual(
            self.fixture.registry.ingest_release(first)["state"], "accepted"
        )
        self.assertEqual(
            self.fixture.registry.ingest_release(second)["state"], "quarantined"
        )
        incoming = self.fixture.registry.incoming(
            subject_me_id="dm:being:v1:" + b64url(bytes(range(32))),
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=first["artifact_id"],
        )
        self.assertEqual(incoming["snapshot_core"]["state"], "quarantined")
        self.assertIn("fork", incoming["snapshot_core"]["reason_codes"])

    def test_late_sibling_quarantines_descendants_without_lowering_high_water(
        self,
    ) -> None:
        genesis, release = self.activate_lineage()
        first = self.fixture.successor(genesis, release, label="first")
        self.assertEqual(
            self.fixture.registry.ingest_release(first)["state"], "accepted"
        )
        descendant = self.fixture.successor(genesis, first, label="descendant")
        self.assertEqual(
            self.fixture.registry.ingest_release(descendant)["state"], "accepted"
        )
        sibling = self.fixture.successor(genesis, release, label="late-sibling")
        self.assertEqual(
            self.fixture.registry.ingest_release(sibling)["state"], "quarantined"
        )
        child = self.fixture.successor(genesis, first, label="fork-child")
        self.assertEqual(
            self.fixture.registry.ingest_release(child)["state"], "quarantined"
        )
        incoming = self.fixture.registry.incoming(
            subject_me_id="dm:being:v1:" + b64url(bytes(range(32))),
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=descendant["artifact_id"],
        )
        cursor = incoming["snapshot_core"]["registry_cursor"]
        self.assertEqual(cursor["greatest_observed"], {"epoch": 0, "sequence": 2})
        self.assertEqual(cursor["accepted_head"]["artifact_id"], release["artifact_id"])

    def test_historical_exact_replay_never_downgrades_accepted_head(self) -> None:
        genesis, release = self.activate_lineage()
        successor = self.fixture.successor(genesis, release, label="head")
        self.fixture.registry.ingest_release(successor)
        self.assertEqual(
            self.fixture.registry.ingest_release(release)["state"], "accepted"
        )
        incoming = self.fixture.registry.incoming(
            subject_me_id="dm:being:v1:" + b64url(bytes(range(32))),
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=successor["artifact_id"],
        )
        self.assertEqual(
            incoming["snapshot_core"]["registry_cursor"]["accepted_head"][
                "artifact_id"
            ],
            successor["artifact_id"],
        )

    def test_fork_resolution_closes_epoch_and_late_old_sibling_is_superseded(
        self,
    ) -> None:
        genesis, release = self.activate_lineage()
        left = self.fixture.successor(genesis, release, label="left")
        right = self.fixture.successor(genesis, release, label="right")
        self.fixture.registry.ingest_release(left)
        self.fixture.registry.ingest_release(right)
        resolution = self.fixture.fork_resolution(genesis, release, [left, right])
        self.assertEqual(
            self.fixture.registry.ingest_release(resolution)["state"], "accepted"
        )
        late = self.fixture.successor(genesis, release, label="late-after-close")
        self.assertEqual(
            self.fixture.registry.ingest_release(late)["state"], "superseded"
        )
        incoming = self.fixture.registry.incoming(
            subject_me_id="dm:being:v1:" + b64url(bytes(range(32))),
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=resolution["artifact_id"],
        )
        cursor = incoming["snapshot_core"]["registry_cursor"]
        self.assertEqual(
            cursor["accepted_head"]["artifact_id"], resolution["artifact_id"]
        )
        self.assertEqual(cursor["closed_epoch_high_water"]["closed_epoch"], 0)

    def test_fork_resolution_requires_fresh_possession_from_every_resulting_key(
        self,
    ) -> None:
        genesis, release = self.activate_lineage()
        left = self.fixture.successor(genesis, release, label="left")
        right = self.fixture.successor(genesis, release, label="right")
        self.fixture.registry.ingest_release(left)
        self.fixture.registry.ingest_release(right)
        pending = self.fixture.fork_resolution(
            genesis, release, [left, right], possessors=[]
        )
        self.assertEqual(
            self.fixture.registry.ingest_release(pending)["state"], "pending"
        )

    def test_incoming_bootstrap_application_and_current_projection(self) -> None:
        _genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(bytes(range(32)))
        policy_ref = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": True,
                "policy_version": "synthetic-1",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        incoming = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        self.assertTrue(incoming["snapshot_core"]["application_eligible"])

        operation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        contract_schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/species/v0/contracts.schema.json"
            ).read_bytes()
        )
        contract_validator = Draft202012Validator(contract_schema)
        appended_payloads: list[Mapping[str, Any]] = []

        def append(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            contract_validator.validate(payload)
            appended_payloads.append(payload)
            return {
                "being_ref": subject,
                "causal_parents": [],
                "content_hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
                "event_id": str(
                    uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                ),
                "kind": APPLICATION_EVENT_KIND,
                "payload": payload,
                "subject": subject,
            }

        result = self.fixture.registry.apply(
            operation_id=operation_id,
            snapshot=incoming,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=self.root / "runtime.pointer",
            applied_at_ms=4,
            append_event=append,
        )
        self.assertEqual(result["result"], "applied")
        self.assertEqual(len(appended_payloads), 1)
        self.assertEqual(
            appended_payloads[0]["schema"],
            "daimon-species-release-application/v0",
        )
        current = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        self.assertEqual(current["snapshot_core"]["state"], "current")

    def test_application_crashes_before_event_roll_back_unrecorded_pointer(
        self,
    ) -> None:
        _genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(bytes(range(32)))
        policy_ref = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": True,
                "policy_version": "crash-test",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        pointer = self.root / "crash-runtime.pointer"

        def append_never(_payload: Mapping[str, Any]) -> Mapping[str, Any]:
            self.fail("event append must not run before the injected crash")

        for operation_id, phase in (
            ("11111111-1111-4111-8111-111111111111", "after_application_prepared"),
            (
                "22222222-2222-4222-8222-222222222222",
                "after_application_pointer_switch",
            ),
        ):
            with self.subTest(phase=phase):

                def fault(current: str, *, expected: str = phase) -> None:
                    if current == expected:
                        raise RuntimeError("synthetic_crash")

                with self.assertRaisesRegex(RuntimeError, "synthetic_crash"):
                    self.fixture.registry.apply(
                        operation_id=operation_id,
                        snapshot=snapshot,
                        local_policy_ref=policy_ref,
                        capability_grant_set_hash=b64url(
                            hashlib.sha256(b"grants").digest()
                        ),
                        pointer_path=pointer,
                        applied_at_ms=30,
                        append_event=append_never,
                        fault_hook=fault,
                    )
                self.assertEqual(
                    self.fixture.registry.recover_application(operation_id, pointer),
                    "rolled-back",
                )
                self.assertFalse(pointer.exists())

    def test_application_crash_after_durable_event_completes_exact_commit(self) -> None:
        _genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(bytes(range(32)))
        policy_ref = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": True,
                "policy_version": "event-crash-test",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        operation_id = "33333333-3333-4333-8333-333333333333"
        pointer = self.root / "durable-event-runtime.pointer"
        durable: dict[str, Mapping[str, Any]] = {}

        def append(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            event_id = str(uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND))
            event = {
                "being_ref": subject,
                "causal_parents": [],
                "content_hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
                "event_id": event_id,
                "kind": APPLICATION_EVENT_KIND,
                "payload": payload,
                "subject": subject,
            }
            durable[event_id] = event
            return event

        def fault(phase: str) -> None:
            if phase == "after_application_event":
                raise RuntimeError("synthetic_crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic_crash"):
            self.fixture.registry.apply(
                operation_id=operation_id,
                snapshot=snapshot,
                local_policy_ref=policy_ref,
                capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
                pointer_path=pointer,
                applied_at_ms=31,
                append_event=append,
                fault_hook=fault,
            )
        self.assertTrue(pointer.exists())
        self.assertEqual(
            self.fixture.registry.recover_application(
                operation_id,
                pointer,
                find_event=lambda event_id: durable.get(event_id),
            ),
            "committed",
        )
        self.assertEqual(
            self.fixture.registry.recover_application(
                operation_id,
                pointer,
                find_event=lambda event_id: durable.get(event_id),
            ),
            "committed",
        )

    def test_over_64_release_path_requires_and_records_complete_bound_page_set(
        self,
    ) -> None:
        genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(bytes(range(32)))
        policy_ref = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": True,
                "policy_version": "paging-test",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        pointer = self.root / "paging-runtime.pointer"

        def append_for(
            operation_id: str,
        ) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
            def append(payload: Mapping[str, Any]) -> Mapping[str, Any]:
                previous = payload["previous_application"]
                return {
                    "being_ref": subject,
                    "causal_parents": (
                        [] if previous is None else [previous["event_id"]]
                    ),
                    "content_hash": hashlib.sha256(
                        canonical_bytes(payload)
                    ).hexdigest(),
                    "event_id": str(
                        uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                    ),
                    "kind": APPLICATION_EVENT_KIND,
                    "payload": payload,
                    "subject": subject,
                }

            return append

        bootstrap = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        first_operation = "44444444-4444-4444-8444-444444444444"
        self.fixture.registry.apply(
            operation_id=first_operation,
            snapshot=bootstrap,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=pointer,
            applied_at_ms=40,
            append_event=append_for(first_operation),
        )
        head = release
        for index in range(65):
            head = self.fixture.successor(
                genesis, head, label=f"paging-{index + 1:02d}"
            )
            self.assertEqual(
                self.fixture.registry.ingest_release(head)["state"], "accepted"
            )
        first_page = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=head["artifact_id"],
            local_policy_ref=policy_ref,
        )
        self.assertFalse(first_page["snapshot_core"]["application_eligible"])
        self.assertIsNotNone(
            first_page["snapshot_core"]["path_page"]["continuation_release"]
        )
        occupied_hash = first_page["snapshot_core"]["registry_cursor"][
            "occupied_positions_hash"
        ]
        with self.assertRaisesRegex(SpeciesError, "incoming_page_cursor_required"):
            self.fixture.registry.incoming(
                subject_me_id=subject,
                species_id=self.fixture.species_id,
                enrollment_release_id=release["artifact_id"],
                selected_candidate_id=head["artifact_id"],
                local_policy_ref=policy_ref,
                page_index=1,
            )
        final_page = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=head["artifact_id"],
            local_policy_ref=policy_ref,
            page_index=1,
            expected_occupied_positions_hash=occupied_hash,
        )
        self.assertTrue(final_page["snapshot_core"]["application_eligible"])
        self.assertIsNone(
            final_page["snapshot_core"]["path_page"]["continuation_release"]
        )
        second_operation = "55555555-5555-4555-8555-555555555555"
        result = self.fixture.registry.apply(
            operation_id=second_operation,
            snapshot=final_page,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=pointer,
            applied_at_ms=41,
            append_event=append_for(second_operation),
        )
        self.assertEqual(result["result"], "applied")

    def test_late_release_fork_rolls_runtime_back_to_last_applied_unforked_head(
        self,
    ) -> None:
        genesis, release = self.activate_lineage()
        subject = "dm:being:v1:" + b64url(bytes(range(32)))
        policy_ref = self.fixture.registry.store_local_policy(
            {
                "allowed_species": [self.fixture.species_id],
                "auto_apply": True,
                "policy_version": "fork-rollback-test",
                "resource_profile_ref": self.fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        pointer = self.root / "fork-rollback-runtime.pointer"

        def append_for(
            operation_id: str,
        ) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
            def append(payload: Mapping[str, Any]) -> Mapping[str, Any]:
                previous = payload["previous_application"]
                return {
                    "being_ref": subject,
                    "causal_parents": (
                        [] if previous is None else [previous["event_id"]]
                    ),
                    "content_hash": hashlib.sha256(
                        canonical_bytes(payload)
                    ).hexdigest(),
                    "event_id": str(
                        uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                    ),
                    "kind": APPLICATION_EVENT_KIND,
                    "payload": payload,
                    "subject": subject,
                }

            return append

        bootstrap_snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        bootstrap_operation = "66666666-6666-4666-8666-666666666666"
        self.fixture.registry.apply(
            operation_id=bootstrap_operation,
            snapshot=bootstrap_snapshot,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=pointer,
            applied_at_ms=50,
            append_event=append_for(bootstrap_operation),
        )
        first = self.fixture.successor(genesis, release, label="applied-first")
        second = self.fixture.successor(genesis, first, label="applied-second")
        self.fixture.registry.ingest_release(first)
        self.fixture.registry.ingest_release(second)
        forward_snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            selected_candidate_id=second["artifact_id"],
            local_policy_ref=policy_ref,
        )
        forward_operation = "77777777-7777-4777-8777-777777777777"
        self.fixture.registry.apply(
            operation_id=forward_operation,
            snapshot=forward_snapshot,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=pointer,
            applied_at_ms=51,
            append_event=append_for(forward_operation),
        )
        sibling = self.fixture.successor(genesis, release, label="late-fork")
        self.assertEqual(
            self.fixture.registry.ingest_release(sibling)["state"], "quarantined"
        )
        rollback_snapshot = self.fixture.registry.incoming(
            subject_me_id=subject,
            species_id=self.fixture.species_id,
            enrollment_release_id=release["artifact_id"],
            local_policy_ref=policy_ref,
        )
        self.assertEqual(rollback_snapshot["snapshot_core"]["state"], "quarantined")
        rollback_operation = "88888888-8888-4888-8888-888888888888"
        result = self.fixture.registry.rollback(
            operation_id=rollback_operation,
            snapshot=rollback_snapshot,
            local_policy_ref=policy_ref,
            capability_grant_set_hash=b64url(hashlib.sha256(b"grants").digest()),
            pointer_path=pointer,
            applied_at_ms=52,
            reason="release-fork",
            append_event=append_for(rollback_operation),
        )
        self.assertEqual(result["result"], "rolled-back")
        active_runtime = json.loads(pointer.read_bytes())
        self.assertEqual(
            active_runtime["release"]["artifact_id"], release["artifact_id"]
        )

    def test_runner_rejects_randomness_import(self) -> None:
        module = bytes(
            wasmtime.wat2wasm(
                """(module
                  (import "wasi_snapshot_preview1" "random_get"
                    (func $random (param i32 i32) (result i32)))
                  (memory (export "memory") 1)
                  (func (export "run")
                    (drop (call $random (i32.const 0) (i32.const 1)))))"""
            )
        )
        with self.assertRaisesRegex(SpeciesRunnerError, "runner_forbidden_import"):
            DeterministicWasiRunner().run(
                case_id="randomness",
                module_bytes=module,
                export_name="run",
                input_bytes=b"",
                bundle_files={},
                dependency_files={},
                resource_profile=self.fixture.resource_profile,
            )

    def test_runner_enforces_file_limits_over_complete_dependency_closure(
        self,
    ) -> None:
        module = bytes(wasmtime.wat2wasm('(module (func (export "run")))'))
        runner = DeterministicWasiRunner()
        with self.assertRaisesRegex(SpeciesRunnerError, "bundle_filesystem_bytes"):
            runner.run(
                case_id="aggregate-bytes",
                module_bytes=module,
                export_name="run",
                input_bytes=b"",
                bundle_files={"root": b"x" * 3000},
                dependency_files={
                    "dm:species-content:v0:dependency": {"nested": b"y" * 3000}
                },
                resource_profile=self.fixture.resource_profile,
            )
        profile = {**self.fixture.resource_profile, "file_count": 1}
        with self.assertRaisesRegex(SpeciesRunnerError, "bundle_file_count"):
            runner.run(
                case_id="aggregate-count",
                module_bytes=module,
                export_name="run",
                input_bytes=b"",
                bundle_files={"root": b""},
                dependency_files={"dm:species-content:v0:dependency": {"nested": b""}},
                resource_profile=profile,
            )

    def test_wrong_content_bytes_remain_incomplete(self) -> None:
        reference = self.fixture.cas.put(b"right", "application/octet-stream")
        changed = dict(reference)
        changed["content_id"] = "dm:species-content:v0:" + b64url(
            hashlib.sha256(b"wrong").digest()
        )
        with self.assertRaises(SpeciesError):
            self.fixture.cas.get(changed)

    def test_declared_branch_child_genesis_and_release_zero(self) -> None:
        _genesis, parent_release = self.activate_lineage()
        declaration, child_genesis, child_release, _foundation, _child_seeds = (
            self.fixture.branch_material(parent_release)
        )
        self.assertEqual(
            self.fixture.registry.ingest_release(declaration)["state"], "accepted"
        )
        child_state = self.fixture.registry.ingest_genesis(child_genesis)
        self.assertEqual(child_state["state"], "active")
        self.assertNotEqual(child_state["species_id"], self.fixture.species_id)
        self.assertEqual(
            self.fixture.registry.ingest_release(child_release)["state"], "accepted"
        )
        birth_context = self.fixture.registry.birth_context(
            child_release["artifact_id"],
            parent_enrollment_release_id=parent_release["artifact_id"],
        )
        self.assertEqual(birth_context["state"], "valid")
        parent_carrier = self.fixture.registry.incoming(
            subject_me_id="dm:being:v1:" + b64url(bytes(range(32))),
            species_id=self.fixture.species_id,
            enrollment_release_id=parent_release["artifact_id"],
            selected_candidate_id=child_release["artifact_id"],
        )
        self.assertEqual(parent_carrier["snapshot_core"]["state"], "diverged")
        self.assertFalse(parent_carrier["snapshot_core"]["application_eligible"])
        racing_parent_successor = self.fixture.successor(
            self.fixture.genesis(), parent_release, label="racing-parent-successor"
        )
        self.assertEqual(
            self.fixture.registry.ingest_release(racing_parent_successor)["state"],
            "quarantined",
        )
        self.assertEqual(
            self.fixture.registry.birth_context(child_release["artifact_id"])["state"],
            "quarantined",
        )

    def test_missing_or_legacy_birth_species_only_quarantines_provenance(self) -> None:
        missing = "dm:species-release:v0:" + b64url(hashlib.sha256(b"missing").digest())
        self.assertEqual(
            self.fixture.registry.birth_context(missing)["state"],
            "context-incomplete",
        )
        self.assertEqual(
            self.fixture.registry.birth_context("legacy-species-label")["state"],
            "quarantined",
        )

    def test_noop_branch_has_no_species_authority(self) -> None:
        with self.assertRaisesRegex(SpeciesError, "branch_no_breaking_delta"):
            CompatibilityVerifier(self.fixture.cas).build_breaking_delta(
                parent_genome=self.fixture.genome,
                child_genome=self.fixture.genome,
            )


class HostedSpeciesRuntimeTests(RuntimeFixture):
    def test_v4_bundle_schema_loads_species_and_serves_authenticated_preview(
        self,
    ) -> None:
        state_root, bundle, capability = self.make_bundle(state_name="species-v4")
        fixture = SpeciesFixture(state_root)
        policy_ref = fixture.registry.store_local_policy(
            {
                "allowed_species": [fixture.species_id],
                "auto_apply": True,
                "policy_version": "hosted-v4",
                "resource_profile_ref": fixture.resource_ref,
                "schema": "daimon-species-local-application-policy/v0",
            }
        )
        bundle.update(
            {
                "authority_history": [],
                "peer_transport": None,
                "schema": "dm.runtime.bundle/v4",
                "species": {
                    "cas_filename": "cas.sqlite3",
                    "enrollment_release_id": (
                        "dm:species-release:v0:"
                        + b64url(hashlib.sha256(b"enrollment").digest())
                    ),
                    "local_policy_ref": policy_ref,
                    "pointer_filename": "species.pointer",
                    "registry_filename": "registry.sqlite3",
                    "species_id": fixture.species_id,
                },
            }
        )
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/hosted/v4/bundle.schema.json"
            ).read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(bundle)
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(bundle))
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        request = create_request(
            capability,
            request_id="06100000-0000-4000-8000-000000000100",
            issued_at_ms=NOW,
            method="species.incoming",
            params={
                "expected_occupied_positions_hash": None,
                "page_index": 0,
                "selected_candidate_id": None,
            },
            nonce=b"s" * 16,
        )
        response = runtime.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["snapshot_core"]["state"], "incomplete")

        collision = copy.deepcopy(bundle)
        collision["species"]["pointer_filename"] = collision["ledger"]
        bundle_path.write_bytes(canonical_bytes(collision))
        with self.assertRaisesRegex(HostedRuntimeError, "runtime_filename_collision"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
