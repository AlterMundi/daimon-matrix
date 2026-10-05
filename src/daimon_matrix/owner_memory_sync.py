"""Human-triggered host-local memory comparison and sync operations.

This operator never polls an inbox or invokes a model. Pool row hashes describe
local projection/native state; they do not prove Matrix authorship or authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any, cast

from .memory_projection import HMK_COMMIT
from .owner_sync.durable_rebuild_packet import load_saved_rebuilds, save_rebuild_packet
from .owner_sync.locked_projection_operation import (
    bound_projection_runtime,
    execute_selected_projection,
)
from .owner_sync.namespace_rebuild_operation import (
    RebuildTransport,
    apply_rebuilds,
    prepare_rebuilds,
)
from .owner_sync.native_reconcile import (
    NativeAPI,
    apply,
    digest,
    native_history,
    prepare,
    read_state,
)
from .owner_sync.selected_projection_kernel import NativeTransport, checked_bytes
from .runtime import _owner_directory, _safe_file


def read_private_packet(path: Path, sha256: str) -> dict[str, Any]:
    path = path.absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=True)
    document = json.loads(checked_bytes(path, sha256))
    if not isinstance(document, dict):
        raise ValueError("owner_memory_packet_object_required")
    return cast(dict[str, Any], document)


def check_native_checkout(root: Path) -> Path:
    """Admit the exact clean native contract, without importing it in this body."""
    root = root.absolute()
    for ancestor in (root, *root.parents):
        if ancestor.is_symlink():
            raise ValueError("native_checkout_alias_refused")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()
    if head != HMK_COMMIT or status:
        raise ValueError("native_checkout_pin_or_content_drift")
    return root / "scripts/daimon_projection.py"


def execute_projection_packet(
    *,
    packet: Path,
    sha256: str,
    profile_root: Path,
    content_root: Path,
    native_root: Path,
    python: Path,
    isolated_home: Path,
    initial_pool_sha256: str,
) -> dict[str, Any]:
    """Apply exactly selected accepted heads under the official runtime lock.

    Invocation must be explicitly approved with the outer writer cutoff and
    verified pool/journal backups. No service, source intake or custody loading.
    """
    plan = read_private_packet(packet, sha256)
    script = check_native_checkout(native_root)
    _owner_directory(isolated_home)
    transport = NativeTransport(
        python=python,
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        pool=plan["target_pool_proposal"],
        instance=plan["target_instance"],
        isolated_home=isolated_home,
    )
    entries = execute_selected_projection(
        plan=plan,
        profile_root=profile_root,
        content_root=content_root,
        transport=transport,
        expected_initial_pool_sha256=initial_pool_sha256,
    )
    return {
        "schema": "dm.owner-selected-projection-result/v1",
        "plan_sha256": sha256,
        "entries": entries,
        "source_ledger_mutated": False,
    }


def rebuild_projection_packet(
    *,
    packet: Path,
    sha256: str,
    profile_root: Path,
    content_root: Path,
    native_root: Path,
    python: Path,
    isolated_home: Path,
    saved: Path,
    saved_sha256: str | None,
) -> dict[str, Any]:
    """Prepare once or apply exactly retained SDK namespace plans under lock."""
    plan = read_private_packet(packet, sha256)
    script = check_native_checkout(native_root)
    _owner_directory(isolated_home)
    transport = RebuildTransport(
        python=python,
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        pool=plan["target_pool_proposal"],
        instance=plan["target_instance"],
        isolated_home=isolated_home,
    )
    with bound_projection_runtime(plan=plan, transport=transport) as (ledger, _):
        if saved_sha256 is None:
            saved = saved.absolute()
            _owner_directory(saved.parent)
            _safe_file(saved.parent, saved.name, must_exist=False)
            if saved.exists() or saved.is_symlink():
                raise FileExistsError("saved_rebuild_destination_occupied")
            prepared = prepare_rebuilds(
                ledger=ledger,
                entries=plan["entries"],
                profile_root=profile_root,
                content_root=content_root,
                transport=transport,
            )
            pin = save_rebuild_packet(prepared, saved)
            return {
                "schema": "dm.owner-namespace-rebuild-preparation/v1",
                "selection_sha256": sha256,
                "saved_plan_sha256": pin,
                "namespaces": len(prepared),
                "adoption_authorized": False,
            }
        saved_document = read_private_packet(saved, saved_sha256)
        if saved_document.get("entries") != plan["entries"]:
            raise ValueError("saved_rebuild_selection_mismatch")
        prepared = load_saved_rebuilds(
            ledger=ledger,
            path=saved,
            sha256=saved_sha256,
            profile_root=profile_root,
            content_root=content_root,
            transport=transport,
        )
        summaries = apply_rebuilds(prepared)
        return {
            "schema": "dm.owner-namespace-rebuild-result/v1",
            "selection_sha256": sha256,
            "saved_plan_sha256": saved_sha256,
            "entries": summaries,
            "source_ledger_mutated": False,
        }


def projection_states(path: Path) -> dict[str, list[str]]:
    """Hash semantic projection metadata by claimed origin; never infer signatures.

    Local chapter IDs and adapter receipts can differ across hosts. Head, content,
    active status and origin namespace identity are the relevant projected state.
    """
    with closing(
        sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {"daimon_projections", "daimon_projection_namespaces"}
        if not names & required:
            return {}
        if not required <= names:
            raise ValueError("incomplete_projection_schema")
        result: dict[str, list[str]] = {}
        query = """SELECT n.source_instance, n.subject_me_id, n.projector_id,
            n.projector_version, p.memory_id, p.author_me_id, p.category,
            p.classification, p.head_event_id, p.head_event_hash, p.statement_hash,
            p.statement_length, p.statement_media_type, p.active
            FROM daimon_projections p LEFT JOIN daimon_projection_namespaces n
            ON p.namespace_id=n.namespace_id"""
        for row in connection.execute(query):
            values = dict(row)
            identity = {
                key: values.pop(key)
                for key in (
                    "source_instance",
                    "subject_me_id",
                    "projector_id",
                    "projector_version",
                )
            }
            if any(value is None for value in identity.values()):
                raise ValueError("projection_namespace_missing")
            result.setdefault(digest(identity), []).append(digest(values))
        return {key: sorted(values) for key, values in result.items()}


def publish_private_packet(path: Path, document: dict[str, Any]) -> str:
    """Publish private preparation once; no overwrite or effect on either pool."""
    path = path.absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=False)
    raw = (
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("owner_memory_packet_too_large")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".owner-memory-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()


def prepare_native_packet(
    *,
    source: Path,
    target: Path,
    source_label: str,
    target_label: str,
    state: Path,
    output: Path,
) -> dict[str, Any]:
    if any(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label) is None
        for label in (source_label, target_label)
    ):
        raise ValueError("invalid_native_pool_lineage")
    plan = prepare(
        source_db=source.absolute(),
        target_db=target.absolute(),
        source_label=source_label,
        target_label=target_label,
        state=read_state(state.absolute()),
    )
    sha256 = publish_private_packet(output, plan)
    return {
        "schema": "dm.owner-native-sync-preparation/v1",
        "plan_sha256": sha256,
        "native_plan_id": plan["plan_id"],
        "reuse": sum(entry["action"] == "reuse" for entry in plan["entries"]),
        "import": sum(entry["action"] == "import" for entry in plan["entries"]),
        "protected_projection_chapters": len(plan["protected_ids"]),
        "source_mutated": False,
        "target_mutated": False,
        "adoption_authorized": False,
    }


def _native_worker(
    packet: Path, sha256: str, native_root: Path, target: Path, state: Path
) -> dict[str, Any]:
    """Installed worker, called only inside the owner's locked stripped process."""
    plan = read_private_packet(packet, sha256)
    check_native_checkout(native_root)
    script = native_root / "scripts/memoryctl.py"
    sys.path.insert(0, str(script.parent))
    specification = importlib.util.spec_from_file_location("owner_native_hmk", script)
    if specification is None or specification.loader is None:
        raise ValueError("native_api_loader_unavailable")
    api = importlib.util.module_from_spec(specification)
    # Native diagnostics may contain imported titles. The parent discards them
    # on failure and admits only the final content-free JSON result on success.
    specification.loader.exec_module(api)
    summaries = apply(
        plan=plan, target_db=target, api=cast(NativeAPI, api), state_path=state
    )
    return {
        "schema": "dm.owner-native-sync-result/v1",
        "plan_sha256": sha256,
        "native_plan_id": plan["plan_id"],
        "entries": summaries,
        "source_ledger_mutated": False,
    }


def execute_native_packet(
    *,
    packet: Path,
    sha256: str,
    binding: Path,
    binding_sha256: str,
    state: Path,
    native_root: Path,
    python: Path,
    isolated_home: Path,
) -> dict[str, Any]:
    """Apply a retained native plan with public runtime binding and writer lock.

    This lock excludes the Matrix owner only. Human-approved consumer cutoff
    and pool/provenance backups are still required outside this command.
    """
    native_plan = read_private_packet(packet, sha256)
    if (
        digest({k: v for k, v in native_plan.items() if k != "plan_id"})
        != (native_plan["plan_id"])
    ):
        raise ValueError("native_sync_plan_integrity_failed")
    plan = read_private_packet(binding, binding_sha256)
    script = check_native_checkout(native_root)
    _owner_directory(isolated_home)
    state = state.absolute()
    _owner_directory(state.parent)
    _safe_file(state.parent, state.name, must_exist=False)
    read_state(state)
    transport = NativeTransport(
        python=python,
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        pool=plan["target_pool_proposal"],
        instance=plan["target_instance"],
        isolated_home=isolated_home,
    )
    with bound_projection_runtime(plan=plan, transport=transport) as (_, database):
        # -I discards PYTHONPATH/user site; -B prevents native checkout mutation.
        # The selected SDK interpreter must have this exact operator installed.
        code = (
            "import json,sys; from pathlib import Path; "
            "from daimon_matrix.owner_memory_sync import _native_worker; "
            "r=_native_worker(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),"
            "Path(sys.argv[4]),Path(sys.argv[5])); print(json.dumps(r))"
        )
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                code,
                str(packet.absolute()),
                sha256,
                str(native_root.absolute()),
                str(database),
                str(state),
            ],
            env=transport.environment,
            cwd=isolated_home,
            capture_output=True,
            timeout=900,
            check=False,
        )
        if result.returncode:
            raise ValueError("owner_native_worker_failed_retain_plan_and_provenance")
        document = json.loads(result.stdout)
        if (
            not isinstance(document, dict)
            or document.get("schema") != "dm.owner-native-sync-result/v1"
            or document.get("plan_sha256") != sha256
            or document.get("native_plan_id") != native_plan["plan_id"]
        ):
            raise ValueError("owner_native_worker_result_mismatch")
        return cast(dict[str, Any], document)


def compare_pools(left: Path, right: Path) -> dict[str, Any]:
    """Compare canonical row digests, without exposing native memory content.

    Native tables and projection metadata each use a read-only transaction.
    Source writers must be stopped for a shared operational cutoff; this
    observation is not that fence.
    Query/embedding/suggestion histories remain visibly separate local state.
    """
    histories = [native_history(path.absolute()) for path in (left, right)]
    tables = {}
    for name in histories[0]:
        a, b = histories[0][name], histories[1][name]
        tables[name] = {
            "left_rows": len(a),
            "right_rows": len(b),
            "left_digest": digest(a),
            "right_digest": digest(b),
            "shared_distinct_row_digests": len(set(a) & set(b)),
            "left_only_distinct_row_digests": len(set(a) - set(b)),
            "right_only_distinct_row_digests": len(set(b) - set(a)),
            "equal": a == b,
        }
    projections = [projection_states(path) for path in (left, right)]
    origins = {}
    for origin in sorted(set(projections[0]) | set(projections[1])):
        a, b = projections[0].get(origin, []), projections[1].get(origin, [])
        origins[origin] = {
            "left_rows": len(a),
            "right_rows": len(b),
            "left_digest": digest(a),
            "right_digest": digest(b),
            "equal": a == b,
        }
    return {
        "schema": "dm.owner-memory-pool-comparison/v1",
        "tables": tables,
        "equal_native_tables": all(table["equal"] for table in tables.values()),
        "claimed_projection_origins": origins,
        "equal_projected_states": all(origin["equal"] for origin in origins.values()),
        "authority_verified": False,
        "writer_cutoff_verified": False,
        "source_mutated": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    drift = commands.add_parser("drift", help="Content-free native pool comparison")
    drift.add_argument("--left", type=Path, required=True)
    drift.add_argument("--right", type=Path, required=True)
    native = commands.add_parser(
        "prepare-native", help="Save a private native plan; does not adopt"
    )
    native.add_argument("--source", type=Path, required=True)
    native.add_argument("--target", type=Path, required=True)
    native.add_argument("--source-label", required=True)
    native.add_argument("--target-label", required=True)
    native.add_argument("--state", type=Path, required=True)
    native.add_argument("--output", type=Path, required=True)
    native_apply = commands.add_parser(
        "apply-native", help="Explicitly apply a retained native plan under owner lock"
    )
    native_apply.add_argument("--packet", type=Path, required=True)
    native_apply.add_argument("--sha256", required=True)
    native_apply.add_argument("--binding", type=Path, required=True)
    native_apply.add_argument("--binding-sha256", required=True)
    native_apply.add_argument("--state", type=Path, required=True)
    native_apply.add_argument("--native-root", type=Path, required=True)
    native_apply.add_argument("--python", type=Path, required=True)
    native_apply.add_argument("--isolated-home", type=Path, required=True)
    project = commands.add_parser(
        "project-selected", help="Explicitly apply approved selected signed heads"
    )
    project.add_argument("--packet", type=Path, required=True)
    project.add_argument("--sha256", required=True)
    project.add_argument("--profile-root", type=Path, required=True)
    project.add_argument("--content-root", type=Path, required=True)
    project.add_argument("--native-root", type=Path, required=True)
    project.add_argument("--python", type=Path, required=True)
    project.add_argument("--isolated-home", type=Path, required=True)
    project.add_argument("--initial-pool-sha256", required=True)
    for name in ("prepare-rebuild", "apply-rebuild"):
        rebuild = commands.add_parser(
            name, help="Explicit owner namespace rebuild operation"
        )
        rebuild.add_argument("--packet", type=Path, required=True)
        rebuild.add_argument("--sha256", required=True)
        rebuild.add_argument("--profile-root", type=Path, required=True)
        rebuild.add_argument("--content-root", type=Path, required=True)
        rebuild.add_argument("--native-root", type=Path, required=True)
        rebuild.add_argument("--python", type=Path, required=True)
        rebuild.add_argument("--isolated-home", type=Path, required=True)
        rebuild.add_argument("--saved", type=Path, required=True)
        if name == "apply-rebuild":
            rebuild.add_argument("--saved-sha256", required=True)
        else:
            rebuild.set_defaults(saved_sha256=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "drift":
            result = compare_pools(args.left, args.right)
        elif args.command == "prepare-native":
            result = prepare_native_packet(
                source=args.source,
                target=args.target,
                source_label=args.source_label,
                target_label=args.target_label,
                state=args.state,
                output=args.output,
            )
        elif args.command == "apply-native":
            result = execute_native_packet(
                packet=args.packet,
                sha256=args.sha256,
                binding=args.binding,
                binding_sha256=args.binding_sha256,
                state=args.state,
                native_root=args.native_root,
                python=args.python,
                isolated_home=args.isolated_home,
            )
        elif args.command == "project-selected":
            result = execute_projection_packet(
                packet=args.packet,
                sha256=args.sha256,
                profile_root=args.profile_root,
                content_root=args.content_root,
                native_root=args.native_root,
                python=args.python,
                isolated_home=args.isolated_home,
                initial_pool_sha256=args.initial_pool_sha256,
            )
        else:
            result = rebuild_projection_packet(
                packet=args.packet,
                sha256=args.sha256,
                profile_root=args.profile_root,
                content_root=args.content_root,
                native_root=args.native_root,
                python=args.python,
                isolated_home=args.isolated_home,
                saved=args.saved,
                saved_sha256=args.saved_sha256,
            )
    except (
        OSError,
        ValueError,
        RuntimeError,
        sqlite3.Error,
        TypeError,
        KeyError,
        subprocess.SubprocessError,
    ):
        code = {
            "drift": "owner_memory_pool_comparison_failed",
            "prepare-native": "owner_native_sync_preparation_failed",
            "apply-native": "owner_native_sync_apply_failed",
            "project-selected": "owner_selected_projection_failed",
            "prepare-rebuild": "owner_namespace_rebuild_preparation_failed",
            "apply-rebuild": "owner_namespace_rebuild_apply_failed",
        }[args.command]
        print(json.dumps({"ok": False, "code": code}))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
