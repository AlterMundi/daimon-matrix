"""Deterministic conformance registry runner for synthetic release evidence."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes

REGISTRY_SCHEMA: Final = "dm.conformance.registry/v1"
REPORT_SCHEMA: Final = "dm.conformance.report/v1"
TRANSCRIPT_SCHEMA: Final = "dm.conformance.transcript/v1"
MAX_REGISTRY_BYTES: Final = 512 * 1024
MAX_SCENARIOS: Final = 128
REQUIRED_REGISTRY_SHA256: Final = (
    "6763d3a02d4c826370e51ad4ba66909d64e2a23c9dd9672b026a494b4e4c08e4"
)
REQUIRED_SCENARIO_IDS: Final = frozenset(
    {
        "adapter_storage_non_authority",
        "authority_epoch_succession",
        "canonical_artifacts",
        "causal_quarantine_promotion",
        "cli_closed_retry_surface",
        "cluster_effect_truth",
        "collective_exchange_recovery",
        "collective_publication_review",
        "collective_real_io",
        "collective_source_quarantine",
        "communication_cursor_contiguous",
        "communication_fanout_receipts",
        "communication_route_replay",
        "communication_state_rollback_gc",
        "control_fork_recovery",
        "curator_effect_truth",
        "curator_installed_retry",
        "curator_resource_cas",
        "curator_review_actor",
        "curator_worker_boundary",
        "curator_worker_recovery",
        "custody_disclosure_boundary",
        "daemon_fault_restart",
        "daemon_single_writer_socket",
        "hermes_lifecycle_recovery",
        "hermes_profile_isolation",
        "hermes_provider_boundary",
        "ledger_atomic_equivocation",
        "ledger_concurrent_sequence",
        "ledger_oversize_atomicity",
        "local_we_body_admission",
        "local_we_independent_adoption",
        "local_we_receipt_contract",
        "mcp_modern_closed_surface",
        "mcp_review_decision_refusal",
        "memory_body_authority",
        "memory_category_provenance",
        "memory_deterministic_vectors",
        "memory_installed_surface",
        "memory_lane_fork",
        "memory_policy_succession",
        "memory_projection_effect_truth",
        "memory_projection_migration",
        "memory_projection_rebuild",
        "memory_review_precedence",
        "memory_stale_exact_once",
        "plural_membership",
        "projection_determinism",
        "projection_rebuild_disposable_cache",
        "publication_contract_vectors",
        "publication_effect_truth",
        "publication_recovery",
        "purpose_key_separation",
        "recipient_encryption_isolation",
        "recipient_encryption_retry",
        "recipient_encryption_tamper",
        "revocation_history_cutoff",
        "review_access_possession",
        "review_authority_separation",
        "review_crash_idempotency",
        "review_edit_successor",
        "review_request_exact_binding",
        "review_subject_revalidation",
        "review_threshold_conflict",
        "route_authenticated_loopbacks",
        "route_deterministic_fallback",
        "route_locality_gateway",
        "route_provider_state",
        "rpc_auth_conflict",
        "rpc_exact_durable_replay",
        "scope_dm052_sync_parity",
        "scope_root_resolution",
        "scope_signed_partial_fanout",
        "sqlite_delete_full_integrity",
        "sync_import_not_adoption",
        "sync_resume_cursor",
        "tribe_verified_snapshot",
    }
)
_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_TEST_ID = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{5,255}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SAFE_ARTIFACT_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SCENARIO_FIELDS: Final = {
    "ci_lane",
    "cleanup",
    "evidence",
    "expected",
    "fault",
    "id",
    "owners",
    "platform",
    "required",
    "setup",
    "specifications",
    "stimulus",
}
_FORBIDDEN_REPORT_MARKERS: Final = (
    "-----BEGIN " + "PRIVATE KEY-----",
    "OPENAI_API_KEY=",
    "ANTHROPIC_API_KEY=",
    "XAI_API_KEY=",
    "github_" + "pat_",
    "fixture-password",
)


class ConformanceError(RuntimeError):
    """The registry, execution, or report violated the closed contract."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError("duplicate_json_key")
        result[key] = value
    return result


def _text(value: Any, *, maximum: int = 1024) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise ConformanceError("invalid_registry_text")
    if any(ord(character) < 0x20 and character not in "\n\t" for character in value):
        raise ConformanceError("unsafe_registry_text")
    return value


def _text_list(value: Any, *, maximum_items: int = 32) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        raise ConformanceError("invalid_registry_text_list")
    result = [_text(item, maximum=256) for item in value]
    if result != sorted(set(result)):
        raise ConformanceError("invalid_registry_text_list")
    return result


@dataclass(frozen=True)
class Scenario:
    id: str
    owners: tuple[str, ...]
    specifications: tuple[str, ...]
    setup: str
    stimulus: str
    fault: str
    expected: str
    evidence: tuple[str, ...]
    cleanup: str
    platform: str
    ci_lane: str
    required: bool

    @classmethod
    def from_value(cls, value: Any) -> Scenario:
        if not isinstance(value, Mapping) or set(value) != _SCENARIO_FIELDS:
            raise ConformanceError("invalid_scenario_shape")
        scenario_id = value["id"]
        if not isinstance(scenario_id, str) or _ID.fullmatch(scenario_id) is None:
            raise ConformanceError("invalid_scenario_id")
        owners = _text_list(value["owners"])
        if any(re.fullmatch(r"DM-[0-9]{3}", owner) is None for owner in owners):
            raise ConformanceError("invalid_scenario_owner")
        specifications = _text_list(value["specifications"])
        evidence = _text_list(value["evidence"])
        if any(_TEST_ID.fullmatch(test_id) is None for test_id in evidence):
            raise ConformanceError("invalid_evidence_test_id")
        platform_name = value["platform"]
        ci_lane = value["ci_lane"]
        if platform_name not in {"all", "linux"} or ci_lane not in {
            "fast",
            "complete",
        }:
            raise ConformanceError("invalid_scenario_lane")
        if not isinstance(value["required"], bool):
            raise ConformanceError("invalid_scenario_required")
        return cls(
            id=scenario_id,
            owners=tuple(owners),
            specifications=tuple(specifications),
            setup=_text(value["setup"]),
            stimulus=_text(value["stimulus"]),
            fault=_text(value["fault"]),
            expected=_text(value["expected"]),
            evidence=tuple(evidence),
            cleanup=_text(value["cleanup"]),
            platform=platform_name,
            ci_lane=ci_lane,
            required=value["required"],
        )

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "owners": list(self.owners),
            "specifications": list(self.specifications),
            "setup": self.setup,
            "stimulus": self.stimulus,
            "fault": self.fault,
            "expected": self.expected,
            "evidence": list(self.evidence),
            "cleanup": self.cleanup,
            "platform": self.platform,
            "ci_lane": self.ci_lane,
            "required": self.required,
        }


@dataclass(frozen=True)
class Registry:
    suite_version: str
    fixture_seed: str
    scenarios: tuple[Scenario, ...]
    evidence_root: Path

    @classmethod
    def load(cls, path: Path) -> Registry:
        try:
            raw = path.read_bytes()
        except OSError as exception:
            raise ConformanceError("registry_unavailable") from exception
        if not 1 <= len(raw) <= MAX_REGISTRY_BYTES:
            raise ConformanceError("registry_size_invalid")
        try:
            value = json.loads(raw, object_pairs_hook=_unique_object)
            canonical_bytes(value)
        except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ConformanceError("registry_json_invalid") from exception
        if (
            not isinstance(value, Mapping)
            or set(value) != {"fixture_seed", "scenarios", "schema", "suite_version"}
            or value["schema"] != REGISTRY_SCHEMA
        ):
            raise ConformanceError("registry_shape_invalid")
        suite_version = _text(value["suite_version"], maximum=64)
        fixture_seed = _text(value["fixture_seed"], maximum=128)
        raw_scenarios = value["scenarios"]
        if (
            not isinstance(raw_scenarios, list)
            or not 1 <= len(raw_scenarios) <= MAX_SCENARIOS
        ):
            raise ConformanceError("scenario_count_invalid")
        scenarios = tuple(Scenario.from_value(item) for item in raw_scenarios)
        ids = [scenario.id for scenario in scenarios]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ConformanceError("scenario_ids_not_unique_sorted")
        if set(ids) != REQUIRED_SCENARIO_IDS:
            raise ConformanceError("required_scenario_coverage_mismatch")
        if any(not scenario.required for scenario in scenarios):
            raise ConformanceError("release_registry_scenario_not_required")
        result = cls(
            suite_version,
            fixture_seed,
            scenarios,
            path.resolve().parent.parent,
        )
        if result.digest != REQUIRED_REGISTRY_SHA256:
            raise ConformanceError("registry_digest_mismatch")
        return result

    def public(self) -> dict[str, Any]:
        return {
            "schema": REGISTRY_SCHEMA,
            "suite_version": self.suite_version,
            "fixture_seed": self.fixture_seed,
            "scenarios": [scenario.public() for scenario in self.scenarios],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_bytes(self.public())).hexdigest()


def deterministic_schedule(
    seed: str, actors: Sequence[str], rounds: int
) -> list[list[str]]:
    """Return stable permutations without depending on runtime random algorithms."""

    _text(seed, maximum=128)
    if (
        not isinstance(rounds, int)
        or isinstance(rounds, bool)
        or not 1 <= rounds <= 1024
        or not 1 <= len(actors) <= 256
        or list(actors) != sorted(set(actors))
    ):
        raise ConformanceError("invalid_schedule_input")
    schedule: list[list[str]] = []
    for index in range(rounds):
        schedule.append(
            sorted(
                actors,
                key=lambda actor: hashlib.sha256(
                    f"dm026:{seed}:{index}:{actor}".encode()
                ).digest(),
            )
        )
    return schedule


def platform_facts() -> dict[str, Any]:
    """Measure the real SQLite durability policy in an isolated temporary DB."""

    with tempfile.TemporaryDirectory(prefix="dm026-platform-") as directory:
        database_path = Path(directory) / "policy.sqlite"
        with closing(sqlite3.connect(database_path)) as database:
            journal = str(
                database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            ).lower()
            database.execute("PRAGMA synchronous=FULL")
            synchronous = int(database.execute("PRAGMA synchronous").fetchone()[0])
            database.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
            database.execute("INSERT INTO evidence VALUES ('committed')")
            database.commit()
        with closing(sqlite3.connect(database_path)) as database:
            integrity = str(database.execute("PRAGMA integrity_check").fetchone()[0])
            committed = str(
                database.execute("SELECT value FROM evidence").fetchone()[0]
            )
    if (
        journal != "delete"
        or synchronous != 2
        or integrity != "ok"
        or committed != "committed"
    ):
        raise ConformanceError("sqlite_durability_policy_unavailable")
    return {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
        "journal_mode": journal,
        "synchronous": "FULL",
    }


def _test_exists(test_id: str, source_root: Path) -> None:
    parts = test_id.split(".")
    if len(parts) < 4 or parts[0] != "tests":
        raise ConformanceError(f"evidence_not_exact:{test_id}")
    module_parts = parts[:-2]
    class_name, method_name = parts[-2:]
    relative = Path(*module_parts).with_suffix(".py")
    source = source_root / relative
    if not source.is_file():
        raise ConformanceError(f"evidence_unloadable:{test_id}")
    try:
        tree = ast.parse(source.read_bytes(), filename=str(source))
    except (OSError, SyntaxError, UnicodeDecodeError) as exception:
        raise ConformanceError(f"evidence_unloadable:{test_id}") from exception
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    methods = [
        node
        for class_node in classes
        for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    ]
    if len(classes) != 1 or len(methods) != 1 or not method_name.startswith("test_"):
        raise ConformanceError(f"evidence_not_exact:{test_id}")


def _run_test(test_id: str, source_root: Path) -> tuple[str, str | None]:
    _test_exists(test_id, source_root)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-W",
                "error::ResourceWarning",
                "-m",
                "unittest",
                test_id,
                "-q",
            ],
            check=False,
            capture_output=True,
            timeout=60,
            cwd=source_root,
        )
        diagnostic = completed.stdout + completed.stderr
        if completed.returncode:
            status = "fail"
        elif b"skipped=" in diagnostic:
            status = "skip"
        else:
            status = "pass"
    except subprocess.TimeoutExpired as exception:
        diagnostic = f"timeout:{test_id}:{exception.timeout}".encode()
        status = "fail"
    digest = (
        hashlib.sha256(f"unittest:{status}:{test_id}".encode()).hexdigest()
        if diagnostic
        else None
    )
    return status, digest


def _artifact_hashes(values: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if separator != "=" or _SAFE_ARTIFACT_NAME.fullmatch(name) is None:
            raise ConformanceError("invalid_artifact_argument")
        if name in result:
            raise ConformanceError("duplicate_artifact_argument")
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file():
            raise ConformanceError("artifact_unavailable")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[name] = digest.hexdigest()
    return dict(sorted(result.items()))


def _validated_artifacts(values: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, digest in values.items():
        if (
            not isinstance(name, str)
            or _SAFE_ARTIFACT_NAME.fullmatch(name) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ConformanceError("invalid_artifact_hash")
        result[name] = digest
    return dict(sorted(result.items()))


def build_report(
    registry: Registry,
    *,
    source_commit: str,
    seed: str,
    artifacts: Mapping[str, str],
) -> dict[str, Any]:
    if _COMMIT.fullmatch(source_commit) is None:
        raise ConformanceError("invalid_source_commit")
    _text(seed, maximum=128)
    verified_artifacts = _validated_artifacts(artifacts)
    system = platform.system().lower()
    evidence_results: dict[str, tuple[str, str | None]] = {}
    eligible_evidence = sorted(
        {
            test_id
            for scenario in registry.scenarios
            if scenario.platform == "all" or system == "linux"
            for test_id in scenario.evidence
        }
    )
    execution_schedule = deterministic_schedule(seed, eligible_evidence, 1)
    for test_id in execution_schedule[0]:
        evidence_results[test_id] = _run_test(test_id, registry.evidence_root)
    outcomes: list[dict[str, Any]] = []
    for scenario in registry.scenarios:
        reason: str | None
        if scenario.platform == "linux" and system != "linux":
            status = "skip"
            reason = "platform_requirement"
            failures: list[str] = []
        else:
            statuses = [evidence_results[test_id][0] for test_id in scenario.evidence]
            status = (
                "fail"
                if "fail" in statuses
                else "skip"
                if "skip" in statuses
                else "pass"
            )
            reason = None if status == "pass" else "evidence_not_passed"
            failures = sorted(
                digest
                for test_id in scenario.evidence
                if evidence_results[test_id][0] != "pass"
                for digest in [evidence_results[test_id][1]]
                if digest is not None
            )
        outcomes.append(
            {
                "scenario_id": scenario.id,
                "status": status,
                "reason": reason,
                "evidence": list(scenario.evidence),
                "diagnostic_hashes": failures,
            }
        )
    transcript = {
        "schema": TRANSCRIPT_SCHEMA,
        "suite_version": registry.suite_version,
        "registry_hash": registry.digest,
        "fixture_seed": seed,
        "schedule": execution_schedule,
        "scenarios": outcomes,
    }
    report = {
        "schema": REPORT_SCHEMA,
        "suite_version": registry.suite_version,
        "source_commit": source_commit,
        "registry_hash": registry.digest,
        "fixture_seed": seed,
        "environment": platform_facts(),
        "artifacts": copy.deepcopy(verified_artifacts),
        "transcript": transcript,
        "transcript_sha256": hashlib.sha256(canonical_bytes(transcript)).hexdigest(),
        "release_ready": all(item["status"] == "pass" for item in outcomes),
    }
    raw = canonical_bytes(report)
    text = raw.decode()
    if any(marker in text for marker in _FORBIDDEN_REPORT_MARKERS):
        raise ConformanceError("report_contains_forbidden_marker")
    return report


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ConformanceError("report_parent_invalid")
    raw = canonical_bytes(report) + b"\n"
    temporary = parent / f".{target.name}.tmp-{os.getpid()}"
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


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-conformance", description=__doc__)
    result.add_argument("--registry", type=Path, required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--seed", required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--artifact", action="append", default=[])
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        registry = Registry.load(args.registry)
        if args.seed != registry.fixture_seed:
            raise ConformanceError("fixture_seed_mismatch")
        report = build_report(
            registry,
            source_commit=args.source_commit,
            seed=args.seed,
            artifacts=_artifact_hashes(args.artifact),
        )
        _write_report(args.output, report)
        summary = {
            "schema": "dm.conformance.summary/v1",
            "release_ready": report["release_ready"],
            "report_sha256": hashlib.sha256(canonical_bytes(report)).hexdigest(),
            "transcript_sha256": report["transcript_sha256"],
        }
        sys.stdout.buffer.write(canonical_bytes(summary) + b"\n")
        return 0 if report["release_ready"] else 1
    except (ConformanceError, OSError) as exception:
        print(str(exception), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "REGISTRY_SCHEMA",
    "REPORT_SCHEMA",
    "REQUIRED_SCENARIO_IDS",
    "ConformanceError",
    "Registry",
    "Scenario",
    "build_report",
    "deterministic_schedule",
    "main",
    "parser",
    "platform_facts",
]
