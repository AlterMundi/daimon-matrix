#!/usr/bin/env python3
"""Validate and freeze an offline-only cross-being canary preflight plan."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from daimon_matrix.canonical import CanonicalError, canonical_bytes

PLAN_SCHEMA: Final = "daimon-cross-being-canary-preflight/v1"
RECEIPT_SCHEMA: Final = "daimon-cross-being-canary-preflight-receipt/v1"
MAX_PLAN_BYTES: Final = 256 * 1024
ROOT_FIELDS: Final = {
    "components",
    "human_gates",
    "limitations",
    "participants",
    "purpose",
    "schema",
    "semantic_evidence",
    "steps",
    "transport",
}
COMPONENT_FIELDS: Final = {"artifacts", "commit", "repository", "tree"}
ARTIFACT_FIELDS: Final = {"name", "sha256", "size_bytes"}
PARTICIPANT_FIELDS: Final = {
    "being_ref",
    "consent",
    "custody",
    "endpoint_ref",
    "participant_ref",
}
CONSENT_FIELDS: Final = {"evidence_ref", "inferred", "recorded", "required"}
CUSTODY_FIELDS: Final = {
    "custodian_ref",
    "independence_evidence_ref",
    "independence_verified",
    "must_be_independent",
    "store_ref",
}
TRANSPORT_FIELDS: Final = {
    "endpoint_resolution_allowed",
    "network_access_allowed",
    "transport_ref",
}
SEMANTIC_FIELDS: Final = {
    "matrix_intake_observation_ref",
    "matrix_intake_required",
    "matrix_receipt_observation_ref",
    "matrix_receipt_required",
    "tribe_ack_is_semantic",
    "tribe_ack_satisfies_matrix_intake",
    "tribe_ack_satisfies_matrix_receipt",
}
STEP_FIELDS: Final = {
    "action_ref",
    "effect_refs",
    "id",
    "observation_refs",
    "rollback",
}
ROLLBACK_FIELDS: Final = {"action_ref", "effect_refs", "observation_refs"}
HUMAN_GATE_FIELDS: Final = {
    "custody_verification_complete",
    "exact_go_required",
    "execution_authorized",
    "external_contact_approved",
}
LIMITATION_FIELDS: Final = {
    "offline_only",
    "performs_execution",
    "performs_network_io",
    "tribe_is_transitional_only",
}
COMPONENTS: Final = {
    "daimon-cluster": "https://github.com/nicoechaniz/daimon-cluster",
    "daimon-matrix": "https://github.com/AlterMundi/daimon-matrix",
    "tribe-bridge": "https://github.com/nicoechaniz/tribe-bridge",
}
GIT_HASH: Final = re.compile(r"^[0-9a-f]{40}$")
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
BEING_REF: Final = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
OPAQUE_REF: Final = re.compile(
    r"^opaque:[a-z0-9][a-z0-9._-]{0,31}(?:/[a-z0-9][a-z0-9._-]{0,31}){0,7}$"
)
TOKEN: Final = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
ARTIFACT_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class PreflightError(ValueError):
    """A preflight plan or filesystem boundary is not closed and safe."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreflightError("duplicate_json_key")
        result[key] = value
    return result


def _closed(value: Any, fields: set[str], reason: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PreflightError(reason)
    return value


def _exact_bool(value: Any, expected: bool, reason: str) -> None:
    if value is not expected:
        raise PreflightError(reason)


def _opaque(value: Any, reason: str) -> str:
    if not isinstance(value, str) or OPAQUE_REF.fullmatch(value) is None:
        raise PreflightError(reason)
    return value


def _opaque_list(value: Any, reason: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise PreflightError(reason)
    refs = [_opaque(item, reason) for item in value]
    if refs != sorted(set(refs)):
        raise PreflightError(reason)
    return refs


def _validate_component(name: str, raw: Any) -> None:
    component = _closed(raw, COMPONENT_FIELDS, "invalid_component_shape")
    if component["repository"] != COMPONENTS[name]:
        raise PreflightError("component_repository_mismatch")
    for field in ("commit", "tree"):
        if (
            not isinstance(component[field], str)
            or GIT_HASH.fullmatch(component[field]) is None
            or component[field] == "0" * 40
        ):
            raise PreflightError(f"invalid_component_{field}")
    raw_artifacts = component["artifacts"]
    if not isinstance(raw_artifacts, list) or not 1 <= len(raw_artifacts) <= 16:
        raise PreflightError("invalid_artifact_count")
    names: list[str] = []
    for raw_artifact in raw_artifacts:
        artifact = _closed(raw_artifact, ARTIFACT_FIELDS, "invalid_artifact_shape")
        artifact_name = artifact["name"]
        if (
            not isinstance(artifact_name, str)
            or ARTIFACT_NAME.fullmatch(artifact_name) is None
        ):
            raise PreflightError("invalid_artifact_name")
        if (
            not isinstance(artifact["sha256"], str)
            or SHA256.fullmatch(artifact["sha256"]) is None
            or artifact["sha256"] == "0" * 64
        ):
            raise PreflightError("invalid_artifact_sha256")
        size = artifact["size_bytes"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= 2**40
        ):
            raise PreflightError("invalid_artifact_size")
        names.append(artifact_name)
    if names != sorted(set(names)):
        raise PreflightError("artifacts_not_unique_sorted")


def _validate_participant(raw: Any) -> dict[str, str]:
    participant = _closed(raw, PARTICIPANT_FIELDS, "invalid_participant_shape")
    being_ref = participant["being_ref"]
    if not isinstance(being_ref, str) or BEING_REF.fullmatch(being_ref) is None:
        raise PreflightError("invalid_being_ref")
    participant_ref = _opaque(participant["participant_ref"], "invalid_participant_ref")
    endpoint_ref = _opaque(participant["endpoint_ref"], "invalid_endpoint_ref")

    consent = _closed(participant["consent"], CONSENT_FIELDS, "invalid_consent_shape")
    _exact_bool(consent["required"], True, "consent_must_be_required")
    _exact_bool(consent["recorded"], False, "consent_must_remain_unrecorded")
    _exact_bool(consent["inferred"], False, "consent_must_not_be_inferred")
    if consent["evidence_ref"] is not None:
        raise PreflightError("consent_evidence_must_be_absent")

    custody = _closed(participant["custody"], CUSTODY_FIELDS, "invalid_custody_shape")
    _exact_bool(
        custody["must_be_independent"], True, "independent_custody_not_required"
    )
    _exact_bool(
        custody["independence_verified"],
        False,
        "custody_verification_must_remain_open",
    )
    if custody["independence_evidence_ref"] is not None:
        raise PreflightError("custody_evidence_must_be_absent")
    custodian_ref = _opaque(custody["custodian_ref"], "invalid_custodian_ref")
    store_ref = _opaque(custody["store_ref"], "invalid_custody_store_ref")
    return {
        "being_ref": being_ref,
        "custodian_ref": custodian_ref,
        "endpoint_ref": endpoint_ref,
        "participant_ref": participant_ref,
        "store_ref": store_ref,
    }


def _validate_steps(raw: Any) -> set[str]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise PreflightError("invalid_step_count")
    ids: list[str] = []
    action_refs: list[str] = []
    rollback_refs: list[str] = []
    observations: set[str] = set()
    for raw_step in raw:
        step = _closed(raw_step, STEP_FIELDS, "invalid_step_shape")
        step_id = step["id"]
        if not isinstance(step_id, str) or TOKEN.fullmatch(step_id) is None:
            raise PreflightError("invalid_step_id")
        ids.append(step_id)
        action_refs.append(_opaque(step["action_ref"], "invalid_action_ref"))
        _opaque_list(step["effect_refs"], "invalid_effect_refs")
        observations.update(
            _opaque_list(step["observation_refs"], "invalid_observation_refs")
        )
        rollback = _closed(step["rollback"], ROLLBACK_FIELDS, "invalid_rollback_shape")
        rollback_refs.append(
            _opaque(rollback["action_ref"], "invalid_rollback_action_ref")
        )
        _opaque_list(rollback["effect_refs"], "invalid_rollback_effect_refs")
        _opaque_list(rollback["observation_refs"], "invalid_rollback_observation_refs")
    if len(ids) != len(set(ids)):
        raise PreflightError("duplicate_step_id")
    if len(action_refs) != len(set(action_refs)):
        raise PreflightError("duplicate_action_ref")
    if len(rollback_refs) != len(set(rollback_refs)):
        raise PreflightError("duplicate_rollback_action_ref")
    return observations


def validate_plan(value: Any) -> dict[str, Any]:
    """Validate a closed, non-authorizing cross-being canary plan."""

    plan = _closed(value, ROOT_FIELDS, "invalid_plan_shape")
    if plan["schema"] != PLAN_SCHEMA or plan["purpose"] != "cross-being-canary":
        raise PreflightError("invalid_plan_identity")

    components = _closed(
        plan["components"], set(COMPONENTS), "invalid_components_shape"
    )
    for name in sorted(COMPONENTS):
        _validate_component(name, components[name])

    participants = _closed(
        plan["participants"], {"side-a", "side-b"}, "invalid_participants_shape"
    )
    sides = [_validate_participant(participants[name]) for name in ("side-a", "side-b")]
    for field in (
        "being_ref",
        "custodian_ref",
        "endpoint_ref",
        "participant_ref",
        "store_ref",
    ):
        if sides[0][field] == sides[1][field]:
            raise PreflightError(f"participant_{field}_must_be_distinct")
    custody_refs = [
        reference
        for side in sides
        for reference in (side["custodian_ref"], side["store_ref"])
    ]
    if len(custody_refs) != len(set(custody_refs)):
        raise PreflightError("all_custody_refs_must_be_distinct")

    transport = _closed(plan["transport"], TRANSPORT_FIELDS, "invalid_transport_shape")
    _opaque(transport["transport_ref"], "invalid_transport_ref")
    _exact_bool(
        transport["network_access_allowed"], False, "network_access_must_be_denied"
    )
    _exact_bool(
        transport["endpoint_resolution_allowed"],
        False,
        "endpoint_resolution_must_be_denied",
    )

    semantic = _closed(
        plan["semantic_evidence"], SEMANTIC_FIELDS, "invalid_semantic_shape"
    )
    expected_semantic_flags = {
        "matrix_intake_required": True,
        "matrix_receipt_required": True,
        "tribe_ack_is_semantic": False,
        "tribe_ack_satisfies_matrix_intake": False,
        "tribe_ack_satisfies_matrix_receipt": False,
    }
    if any(
        semantic[field] is not value for field, value in expected_semantic_flags.items()
    ):
        raise PreflightError("semantic_evidence_policy_mismatch")
    intake_ref = _opaque(
        semantic["matrix_intake_observation_ref"], "invalid_matrix_intake_ref"
    )
    receipt_ref = _opaque(
        semantic["matrix_receipt_observation_ref"], "invalid_matrix_receipt_ref"
    )
    if intake_ref == receipt_ref:
        raise PreflightError("matrix_observation_refs_must_be_distinct")

    observations = _validate_steps(plan["steps"])
    if not {intake_ref, receipt_ref}.issubset(observations):
        raise PreflightError("matrix_observations_missing_from_steps")

    gates = _closed(plan["human_gates"], HUMAN_GATE_FIELDS, "invalid_human_gates_shape")
    expected_gates = {
        "custody_verification_complete": False,
        "exact_go_required": True,
        "execution_authorized": False,
        "external_contact_approved": False,
    }
    if dict(gates) != expected_gates:
        raise PreflightError("human_gates_must_remain_closed")

    limitations = _closed(
        plan["limitations"], LIMITATION_FIELDS, "invalid_limitations_shape"
    )
    expected_limitations = {
        "offline_only": True,
        "performs_execution": False,
        "performs_network_io": False,
        "tribe_is_transitional_only": True,
    }
    if dict(limitations) != expected_limitations:
        raise PreflightError("limitations_mismatch")
    return dict(plan)


def _open_real_parent(
    path: Path, reason: str, *, require_owner_only: bool = False
) -> tuple[int, str]:
    parent = path.parent
    name = path.name
    if not name or name in {".", ".."}:
        raise PreflightError(reason)
    try:
        before = parent.lstat()
    except OSError as exception:
        raise PreflightError(reason) from exception
    if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise PreflightError(reason)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not isinstance(no_follow, int) or not isinstance(directory, int):
        raise PreflightError("platform_lacks_no_symlink_io")
    flags = os.O_RDONLY | directory | no_follow
    try:
        descriptor = os.open(parent, flags)
    except OSError as exception:
        raise PreflightError(reason) from exception
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or (
        require_owner_only
        and (opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700)
    ):
        os.close(descriptor)
        raise PreflightError(reason)
    return descriptor, name


def _read_owner_only_canonical(path: Path) -> tuple[dict[str, Any], bytes]:
    parent_descriptor, name = _open_real_parent(path, "plan_parent_must_be_real")
    try:
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except OSError as exception:
            raise PreflightError("plan_unavailable") from exception
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
        ):
            raise PreflightError("plan_must_be_owner_only_regular_file")
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if not isinstance(no_follow, int):
            raise PreflightError("platform_lacks_no_symlink_io")
        flags = os.O_RDONLY | os.O_NONBLOCK | no_follow
        try:
            descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        except OSError as exception:
            raise PreflightError("plan_open_failed") from exception
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            os.close(descriptor)
            raise PreflightError("plan_changed_during_open")
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(MAX_PLAN_BYTES + 1)
            after = os.fstat(descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(
                getattr(opened, field) != getattr(after, field)
                for field in stable_fields
            ):
                raise PreflightError("plan_changed_during_read")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    if not 1 <= len(raw) <= MAX_PLAN_BYTES:
        raise PreflightError("plan_size_invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        canonical = canonical_bytes(value) + b"\n"
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise PreflightError("plan_json_invalid") from exception
    if raw != canonical:
        raise PreflightError("plan_must_be_canonical_json")
    return validate_plan(value), canonical


def _write_new_owner_only(path: Path, raw: bytes) -> None:
    parent_descriptor, name = _open_real_parent(
        path,
        "output_parent_must_be_real_directory",
        require_owner_only=True,
    )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(no_follow, int):
        os.close(parent_descriptor)
        raise PreflightError("platform_lacks_no_symlink_io")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow
    descriptor: int | None = None
    created = False
    opened: os.stat_result | None = None
    try:
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
            created = True
        except OSError as exception:
            raise PreflightError("output_must_not_exist") from exception
        try:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1
            ):
                raise PreflightError("output_file_untrusted")
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise PreflightError("output_write_failed")
                view = view[written:]
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            stable_fields = ("st_dev", "st_ino", "st_size", "st_nlink")
            if (
                any(
                    getattr(after, field) != getattr(named, field)
                    for field in stable_fields
                )
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_size != len(raw)
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != 0o600
                or after.st_uid != os.geteuid()
            ):
                raise PreflightError("output_changed_during_write")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.read(descriptor, len(raw) + 1) != raw:
                raise PreflightError("output_changed_during_write")
            os.fsync(parent_descriptor)
            final_named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if any(
                getattr(after, field) != getattr(final_named, field)
                for field in stable_fields
            ):
                raise PreflightError("output_changed_during_write")
        finally:
            if descriptor is not None:
                os.close(descriptor)
                descriptor = None
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            with contextlib.suppress(OSError):
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if opened is not None and (current.st_dev, current.st_ino) == (
                    opened.st_dev,
                    opened.st_ino,
                ):
                    os.unlink(name, dir_fd=parent_descriptor)
        raise
    finally:
        os.close(parent_descriptor)


def freeze_plan(input_path: Path, output_path: Path) -> dict[str, Any]:
    """Freeze one validated plan into a non-authorizing content-addressed receipt."""

    plan, plan_bytes = _read_owner_only_canonical(input_path)
    plan_hash = hashlib.sha256(plan_bytes).hexdigest()
    receipt: dict[str, Any] = {
        "execution_authorized": False,
        "external_contact_approved": False,
        "frozen_plan": plan,
        "go_is_authorization": False,
        "plan_sha256": plan_hash,
        "required_go": f"GO {plan_hash}",
        "schema": RECEIPT_SCHEMA,
    }
    _write_new_owner_only(output_path, canonical_bytes(receipt) + b"\n")
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        receipt = freeze_plan(arguments.input, arguments.output)
    except (OSError, PreflightError) as exception:
        print(str(exception), file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["PLAN_SCHEMA", "PreflightError", "freeze_plan", "main", "validate_plan"]
