"""Bounded synthetic DM-061 Species ceremony and recovery evidence.

This module never claims Agent 0, a biological species, a live deployment, or
incompatible adoption by an existing being.  It uses deterministic disposable
keys and owner-only temporary state solely as public conformance evidence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import stat
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import wasmtime

from .canonical import b64url, canonical_bytes
from .species import (
    APPLICATION_EVENT_KIND,
    CompatibilityVerifier,
    SpeciesCAS,
    SpeciesError,
    SpeciesRegistry,
    create_species_genesis,
    create_species_release,
    derive_species_id,
    maintainer_policy_from_seeds,
)

REPORT_SCHEMA: Final = "dm.synthetic-species-report/v0"


class SyntheticSpeciesError(RuntimeError):
    """The isolated synthetic ceremony or public report boundary failed."""


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"dm061:synthetic:{label}".encode()).digest()


def _hash(value: Any) -> str:
    return b64url(hashlib.sha256(canonical_bytes(value)).digest())


def _owner_root(path: Path) -> None:
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise SyntheticSpeciesError("synthetic_species_root_not_owner_only")
    if next(path.iterdir(), None) is not None:
        raise SyntheticSpeciesError("synthetic_species_root_not_empty")


class _Scenario:
    def __init__(self, root: Path) -> None:
        _owner_root(root)
        self.root = root
        self.cas = SpeciesCAS(root / "species-cas.sqlite3")
        self.registry = SpeciesRegistry(root / "species-registry.sqlite3", self.cas)
        self.parent_seeds = [_seed("parent-a"), _seed("parent-b")]
        self.parent_policy = maintainer_policy_from_seeds(self.parent_seeds, 2)
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
        self.resource_ref = self.put(
            self.resource_profile,
            "application/vnd.daimon.species-resource-profile.v0+json",
        )
        semantics_ref = self.put(
            {
                "execution_model": "wasm32-wasi-preview1-deterministic/v0",
                "schema": "species-wasi-semantics/v0",
            },
            "application/vnd.daimon.species-wasi-semantics.v0+json",
        )
        conformance_ref = self.put(
            {
                "runner_version": "wasmtime-python/45.0.0-dm061.1",
                "schema": "species-runner-conformance/v0",
                "verdict": "pass",
            },
            "application/vnd.daimon.species-runner-conformance.v0+json",
        )
        self.runner_ref = self.put(
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
        parent_module = bytes(
            wasmtime.wat2wasm(
                '(module (func (export "verify")) (func (export "invariant")))'
            )
        )
        input_ref = self.cas.put(b"", "application/octet-stream")
        parent_expected = self.put(
            {
                "case_id": "case.compatibility",
                "exit_code": 0,
                "schema": "daimon-test-result-jcs/v0",
                "stderr_base64": "",
                "stdout_base64": "",
            },
            "application/vnd.daimon.daimon-test-result-jcs.v0+json",
        )
        self.input_ref = input_ref
        parent_case = {
            "case_id": "case.compatibility",
            "entrypoint_id": "verify",
            "expected_result_ref": parent_expected,
            "input_ref": input_ref,
        }
        self.parent_suite_ref = self.put(
            {
                "cases": [parent_case],
                "runner_profile_ref": self.runner_ref,
                "schema": "species-suite-manifest/v0",
                "suite_id": "suite.synthetic-core",
                "suite_version": "1",
            },
            "application/vnd.daimon.species-suite-manifest.v0+json",
        )
        invariant_case = {**parent_case, "entrypoint_id": "invariant"}
        self.invariant_ref = self.put(
            {
                "cases": [invariant_case],
                "definition_ref": self.cas.put(
                    b"identity history and authority remain immutable", "text/plain"
                ),
                "invariant_id": "invariant.identity-history-authority",
                "invariant_version": "1",
                "runner_profile_ref": self.runner_ref,
                "schema": "species-invariant-manifest/v0",
            },
            "application/vnd.daimon.species-invariant-manifest.v0+json",
        )
        self.parent_bundle_ref = self.put(
            {
                "dependencies": [],
                "entrypoints": [
                    {"entrypoint_id": "invariant", "export_name": "invariant"},
                    {"entrypoint_id": "verify", "export_name": "verify"},
                ],
                "files": [],
                "module": self.cas.put(parent_module, "application/wasm"),
                "schema": "species-implementation-bundle/v0",
            },
            "application/vnd.daimon.species-implementation-bundle.v0+json",
        )
        contract_ref = self.put(
            {"contract": "synthetic-core", "schema": "synthetic-contract/v0"},
            "application/vnd.daimon.synthetic-contract.v0+json",
        )
        requirement_ref = self.put(
            {"requirement": "deterministic", "schema": "synthetic-requirement/v0"},
            "application/vnd.daimon.synthetic-requirement.v0+json",
        )
        bounds_ref = self.put(
            {"bound": "closed", "schema": "synthetic-bounds/v0"},
            "application/vnd.daimon.synthetic-bounds.v0+json",
        )
        root_ref = self.put(
            {
                "ontology": "being-to-embodiment-to-incarnation",
                "schema": "synthetic-root-me-definition/v0",
            },
            "application/vnd.daimon.synthetic-root-me-definition.v0+json",
        )
        suite_entry = {
            "suite_id": "suite.synthetic-core",
            "suite_ref": self.parent_suite_ref,
            "suite_version": "1",
        }
        invariant_entry = {
            "invariant_id": "invariant.identity-history-authority",
            "invariant_ref": self.invariant_ref,
            "invariant_version": "1",
        }
        self.parent_genome: dict[str, Any] = {
            "capability_contracts": [
                {
                    "contract_id": "contract.synthetic-core",
                    "contract_ref": contract_ref,
                    "version": "1",
                }
            ],
            "compatibility_requirements": {
                "forbidden_authority_changes": ["invariant.identity-history-authority"],
                "required_contract_ids": ["contract.synthetic-core"],
                "required_invariants": [invariant_entry],
                "required_suites": [suite_entry],
                "resource_profile": self.resource_ref,
            },
            "conformance_suites": [suite_entry],
            "implementation_invariants": [invariant_entry],
            "protocol_requirements": [
                {
                    "bounds_ref": bounds_ref,
                    "requirement_id": "protocol.synthetic-core",
                    "requirement_ref": requirement_ref,
                    "version": "1",
                }
            ],
            "root_me_definition": root_ref,
        }
        self.parent_core = {
            "cryptographic_suite": (
                "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"
            ),
            "domain_version": 0,
            "genome": self.parent_genome,
            "initial_maintainers": self.parent_policy,
            "maintainer_floor": {"minimum_key_count": 2, "minimum_threshold": 2},
            "origin": {
                "branch_foundation": None,
                "kind": "primordial",
                "parent_branch_release": None,
            },
            "protocol_version": 0,
            "species_nonce": b64url(_seed("parent-species-nonce")),
        }
        self.parent_species_id = derive_species_id(self.parent_core)

    def put(self, value: Any, media_type: str) -> dict[str, Any]:
        return self.cas.put(canonical_bytes(value), media_type)

    def release(
        self,
        *,
        genesis: Mapping[str, Any],
        predecessor: Mapping[str, Any] | None,
        genome: Mapping[str, Any],
        bundle_ref: Mapping[str, Any],
        policy: Mapping[str, Any],
        species_id: str,
        seeds: Sequence[bytes],
        label: str,
        kind: str = "compatible",
        branch: Mapping[str, Any] | None = None,
        issued_at_ms: int,
    ) -> dict[str, Any]:
        base = (
            None
            if predecessor is None
            else {
                **predecessor["body"],
                "artifact_hash": predecessor["artifact_hash"],
                "artifact_id": predecessor["artifact_id"],
            }
        )
        report = CompatibilityVerifier(self.cas).build_report(
            candidate_genome=genome,
            implementation_bundle=bundle_ref,
            base_release=base,
        )
        prior_position = (
            None if predecessor is None else predecessor["body"]["position"]
        )
        previous_release = None
        if predecessor is not None:
            assert prior_position is not None
            previous_release = {
                "artifact_hash": predecessor["artifact_hash"],
                "artifact_id": predecessor["artifact_id"],
                "epoch": prior_position["epoch"],
                "sequence": prior_position["sequence"],
            }
        body = {
            "authorizing_policy_hash": _hash(policy),
            "branch_declaration": branch,
            "compatibility_report": report,
            "fork_resolution": None,
            "genesis": {
                "artifact_hash": genesis["artifact_hash"],
                "artifact_id": genesis["artifact_id"],
            },
            "genome": genome,
            "implementation_bundle": bundle_ref,
            "issued_at_ms": issued_at_ms,
            "next_maintainers": policy,
            "position": (
                {"epoch": 0, "sequence": 0}
                if prior_position is None
                else {
                    "epoch": prior_position["epoch"],
                    "sequence": prior_position["sequence"] + 1,
                }
            ),
            "previous_release": previous_release,
            "release_kind": "genesis" if predecessor is None else kind,
            "release_label": label,
            "schema": "daimon-species-release/v0",
            "species_id": species_id,
        }
        return create_species_release(body, list(seeds))

    @staticmethod
    def event_appender(
        subject: str, operation_id: str
    ) -> Callable[[Mapping[str, Any]], Mapping[str, Any]]:
        def append(payload: Mapping[str, Any]) -> Mapping[str, Any]:
            previous = payload["previous_application"]
            return {
                "being_ref": subject,
                "causal_parents": [] if previous is None else [previous["event_id"]],
                "content_hash": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
                "event_id": str(
                    uuid.uuid5(uuid.UUID(operation_id), APPLICATION_EVENT_KIND)
                ),
                "kind": APPLICATION_EVENT_KIND,
                "payload": payload,
                "subject": subject,
            }

        return append


def run_synthetic_species(state_root: str | Path) -> dict[str, Any]:
    root = Path(os.path.abspath(state_root))
    scenario = _Scenario(root)
    verifier = CompatibilityVerifier(scenario.cas)
    parent_genesis = create_species_genesis(
        scenario.parent_core,
        scenario.parent_seeds,
        scenario.parent_seeds,
        created_at_ms=1,
    )
    scenario.registry.ingest_genesis(parent_genesis)
    parent_zero = scenario.release(
        genesis=parent_genesis,
        predecessor=None,
        genome=scenario.parent_genome,
        bundle_ref=scenario.parent_bundle_ref,
        policy=scenario.parent_policy,
        species_id=scenario.parent_species_id,
        seeds=scenario.parent_seeds,
        label="synthetic-parent-0",
        issued_at_ms=2,
    )
    scenario.registry.ingest_release(parent_zero)

    child_module = bytes(
        wasmtime.wat2wasm(
            '(module (func (export "verify") unreachable) (func (export "invariant")))'
        )
    )
    child_bundle_ref = scenario.put(
        {
            "dependencies": [],
            "entrypoints": [
                {"entrypoint_id": "invariant", "export_name": "invariant"},
                {"entrypoint_id": "verify", "export_name": "verify"},
            ],
            "files": [],
            "module": scenario.cas.put(child_module, "application/wasm"),
            "schema": "species-implementation-bundle/v0",
        },
        "application/vnd.daimon.species-implementation-bundle.v0+json",
    )
    child_expected_ref = scenario.put(
        {
            "case_id": "case.compatibility",
            "exit_code": 1,
            "schema": "daimon-test-result-jcs/v0",
            "stderr_base64": "",
            "stdout_base64": "",
        },
        "application/vnd.daimon.daimon-test-result-jcs.v0+json",
    )
    child_suite_ref = scenario.put(
        {
            "cases": [
                {
                    "case_id": "case.compatibility",
                    "entrypoint_id": "verify",
                    "expected_result_ref": child_expected_ref,
                    "input_ref": scenario.input_ref,
                }
            ],
            "runner_profile_ref": scenario.runner_ref,
            "schema": "species-suite-manifest/v0",
            "suite_id": "suite.synthetic-core",
            "suite_version": "1",
        },
        "application/vnd.daimon.species-suite-manifest.v0+json",
    )
    child_genome = copy.deepcopy(scenario.parent_genome)
    child_suite = {
        "suite_id": "suite.synthetic-core",
        "suite_ref": child_suite_ref,
        "suite_version": "1",
    }
    child_genome["conformance_suites"] = [child_suite]
    child_genome["compatibility_requirements"]["required_suites"] = [child_suite]
    child_seeds = [_seed("child-a"), _seed("child-b")]
    child_policy = maintainer_policy_from_seeds(child_seeds, 2)
    breaking_delta = verifier.build_breaking_delta(
        parent_genome=scenario.parent_genome, child_genome=child_genome
    )
    branch_report = verifier.build_branch_report(
        parent_genome=scenario.parent_genome,
        child_genome=child_genome,
        child_implementation_bundle=child_bundle_ref,
        breaking_delta=breaking_delta,
    )
    foundation = {
        "branch_nonce": b64url(_seed("branch-nonce")),
        "breaking_delta": breaking_delta,
        "child_genome": child_genome,
        "child_implementation_bundle": child_bundle_ref,
        "child_initial_maintainers": child_policy,
        "child_maintainer_floor": {"minimum_key_count": 2, "minimum_threshold": 2},
        "child_species_nonce": b64url(_seed("child-species-nonce")),
        "incompatibility_report": branch_report,
        "parent_base_release": {
            "artifact_hash": parent_zero["artifact_hash"],
            "artifact_id": parent_zero["artifact_id"],
            "epoch": 0,
            "sequence": 0,
            "species_id": scenario.parent_species_id,
        },
        "parent_species_id": scenario.parent_species_id,
        "schema": "daimon-species-branch-foundation/v0",
    }
    declaration = scenario.release(
        genesis=parent_genesis,
        predecessor=parent_zero,
        genome=scenario.parent_genome,
        bundle_ref=scenario.parent_bundle_ref,
        policy=scenario.parent_policy,
        species_id=scenario.parent_species_id,
        seeds=scenario.parent_seeds,
        label="synthetic-branch-declaration",
        kind="branch-declaration",
        branch=foundation,
        issued_at_ms=3,
    )
    scenario.registry.ingest_release(declaration)
    child_core = {
        **scenario.parent_core,
        "genome": child_genome,
        "initial_maintainers": child_policy,
        "origin": {
            "branch_foundation": foundation,
            "kind": "branch",
            "parent_branch_release": {
                "artifact_hash": declaration["artifact_hash"],
                "artifact_id": declaration["artifact_id"],
                "epoch": 0,
                "sequence": 1,
            },
        },
        "species_nonce": foundation["child_species_nonce"],
    }
    child_species_id = derive_species_id(child_core)
    child_genesis = create_species_genesis(
        child_core, child_seeds, child_seeds, created_at_ms=4
    )
    scenario.registry.ingest_genesis(child_genesis)
    child_zero = scenario.release(
        genesis=child_genesis,
        predecessor=None,
        genome=child_genome,
        bundle_ref=child_bundle_ref,
        policy=child_policy,
        species_id=child_species_id,
        seeds=child_seeds,
        label="synthetic-child-0",
        issued_at_ms=5,
    )
    scenario.registry.ingest_release(child_zero)
    parent_successor = scenario.release(
        genesis=parent_genesis,
        predecessor=declaration,
        genome=scenario.parent_genome,
        bundle_ref=scenario.parent_bundle_ref,
        policy=scenario.parent_policy,
        species_id=scenario.parent_species_id,
        seeds=scenario.parent_seeds,
        label="synthetic-parent-2",
        issued_at_ms=6,
    )
    scenario.registry.ingest_release(parent_successor)

    subject = "dm:being:v1:" + b64url(_seed("synthetic-newborn"))
    policy_ref = scenario.registry.store_local_policy(
        {
            "allowed_species": [scenario.parent_species_id],
            "auto_apply": True,
            "policy_version": "synthetic-v0",
            "resource_profile_ref": scenario.resource_ref,
            "schema": "daimon-species-local-application-policy/v0",
        }
    )
    pointer = root / "species-runtime.pointer"
    capability_hash = b64url(hashlib.sha256(canonical_bytes([])).digest())
    bootstrap = scenario.registry.incoming(
        subject_me_id=subject,
        species_id=scenario.parent_species_id,
        enrollment_release_id=parent_zero["artifact_id"],
        selected_candidate_id=parent_zero["artifact_id"],
        local_policy_ref=policy_ref,
    )
    bootstrap_operation = "06100000-0000-4000-8000-000000000001"
    scenario.registry.apply(
        operation_id=bootstrap_operation,
        snapshot=bootstrap,
        local_policy_ref=policy_ref,
        capability_grant_set_hash=capability_hash,
        pointer_path=pointer,
        applied_at_ms=7,
        append_event=scenario.event_appender(subject, bootstrap_operation),
    )
    forward = scenario.registry.incoming(
        subject_me_id=subject,
        species_id=scenario.parent_species_id,
        enrollment_release_id=parent_zero["artifact_id"],
        selected_candidate_id=parent_successor["artifact_id"],
        local_policy_ref=policy_ref,
    )
    forward_operation = "06100000-0000-4000-8000-000000000002"
    scenario.registry.apply(
        operation_id=forward_operation,
        snapshot=forward,
        local_policy_ref=policy_ref,
        capability_grant_set_hash=capability_hash,
        pointer_path=pointer,
        applied_at_ms=8,
        append_event=scenario.event_appender(subject, forward_operation),
    )
    parent_carrier = scenario.registry.incoming(
        subject_me_id=subject,
        species_id=scenario.parent_species_id,
        enrollment_release_id=parent_zero["artifact_id"],
        selected_candidate_id=child_zero["artifact_id"],
        local_policy_ref=policy_ref,
    )
    sibling = scenario.release(
        genesis=parent_genesis,
        predecessor=declaration,
        genome=scenario.parent_genome,
        bundle_ref=scenario.parent_bundle_ref,
        policy=scenario.parent_policy,
        species_id=scenario.parent_species_id,
        seeds=scenario.parent_seeds,
        label="synthetic-late-sibling",
        issued_at_ms=9,
    )
    fork_result = scenario.registry.ingest_release(sibling)
    fork_snapshot = scenario.registry.incoming(
        subject_me_id=subject,
        species_id=scenario.parent_species_id,
        enrollment_release_id=parent_zero["artifact_id"],
        local_policy_ref=policy_ref,
    )
    rollback_operation = "06100000-0000-4000-8000-000000000003"
    rollback = scenario.registry.rollback(
        operation_id=rollback_operation,
        snapshot=fork_snapshot,
        local_policy_ref=policy_ref,
        capability_grant_set_hash=capability_hash,
        pointer_path=pointer,
        applied_at_ms=10,
        reason="release-fork",
        append_event=scenario.event_appender(subject, rollback_operation),
    )
    runtime = json.loads(pointer.read_bytes())
    birth_context = scenario.registry.birth_context(
        child_zero["artifact_id"],
        parent_enrollment_release_id=parent_zero["artifact_id"],
    )
    report: dict[str, Any] = {
        "application": {
            "bootstrap_operation_id": bootstrap_operation,
            "forward_operation_id": forward_operation,
            "rollback_event_id": rollback["event_id"],
            "rollback_operation_id": rollback_operation,
            "serving_release_id": runtime["release"]["artifact_id"],
        },
        "branch": {
            "breaking_delta_ids": [item["delta_id"] for item in breaking_delta],
            "child_genesis_id": child_genesis["artifact_id"],
            "child_release_id": child_zero["artifact_id"],
            "child_species_id": child_species_id,
            "declaration_release_id": declaration["artifact_id"],
            "newborn_context": birth_context["state"],
            "parent_carrier_state": parent_carrier["snapshot_core"]["state"],
        },
        "fork": {
            "accepted_head_id": fork_snapshot["snapshot_core"]["registry_cursor"][
                "accepted_head"
            ]["artifact_id"],
            "late_sibling_state": fork_result["state"],
            "projection_state": fork_snapshot["snapshot_core"]["state"],
        },
        "parent": {
            "genesis_id": parent_genesis["artifact_id"],
            "release_zero_id": parent_zero["artifact_id"],
            "species_id": scenario.parent_species_id,
        },
        "runner": {
            "package": "wasmtime==45.0.0",
            "version": "wasmtime-python/45.0.0-dm061.1",
        },
        "schema": REPORT_SCHEMA,
        "synthetic": True,
        "verdict": "pass",
    }
    if (
        report["application"]["serving_release_id"] != parent_zero["artifact_id"]
        or report["branch"]["newborn_context"] != "valid"
        or report["branch"]["parent_carrier_state"] != "diverged"
        or report["fork"]["late_sibling_state"] != "quarantined"
        or report["fork"]["projection_state"] != "quarantined"
    ):
        raise RuntimeError("synthetic_species_invariant_failed")
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state-root", help="existing owner-only disposable root")
    result.add_argument("--output", help="write canonical public report to this file")
    return result


def _write_report(path: str | Path, report: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise SyntheticSpeciesError("synthetic_species_report_parent_invalid")
    raw = canonical_bytes(report) + b"\n"
    temporary = parent / f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.state_root is None:
            with tempfile.TemporaryDirectory(prefix="dm-synthetic-species-") as value:
                root = Path(value)
                os.chmod(root, 0o700)
                report = run_synthetic_species(root)
        else:
            report = run_synthetic_species(args.state_root)
        raw = canonical_bytes(report)
        if args.output is None:
            os.write(1, raw + b"\n")
        else:
            _write_report(args.output, report)
        return 0
    except (OSError, SpeciesError, SyntheticSpeciesError) as error:
        os.write(2, (str(error) + "\n").encode("utf-8", "replace")[:512])
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
