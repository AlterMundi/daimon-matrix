"""Explicit, quiesced communication-store upgrade and bounded recovery."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from . import daemon
from .canonical import canonical_bytes
from .communication import (
    HISTORICAL_LEGS_SCHEMA_VERSION,
    CommunicationStore,
    select_persisted_schema,
)
from .ledger import Ledger
from .native_egress import closed_visibility
from .runtime import load_runtime

SCHEMA = "dm.communication-migration/v1"


class MigrationError(RuntimeError):
    """Bounded operator failure, without private state or paths."""


def _file(path: Path) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise MigrationError("migration_file_unsafe")
    if any(parent.is_symlink() for parent in path.parents):
        raise MigrationError("migration_ancestor_symlink")


def _database(path: Path) -> sqlite3.Connection:
    _file(path)
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _digest(database: sqlite3.Connection) -> str:
    digest = hashlib.sha256()
    if database.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise MigrationError("migration_database_corrupt")
    if database.execute("PRAGMA foreign_key_check").fetchall():
        raise MigrationError("migration_foreign_keys_invalid")
    for line in database.iterdump():
        digest.update(line.encode("utf-8") + b"\n")
    return digest.hexdigest()


def state_digest(path: Path) -> str:
    """Digest all logical database state; never return its private dump."""
    with closing(_database(path)) as database:
        database.execute("BEGIN")
        return _digest(database)


def plan(path: Path) -> dict[str, Any]:
    """Read-only preview, with no initialization, key opening or service stop."""
    with closing(_database(path)) as database:
        database.execute("BEGIN")
        row = database.execute(
            "SELECT value FROM communication_meta WHERE key='schema_version'"
        ).fetchone()
        if row is None or str(row[0]) not in {"1", "2", "3", "4"}:
            raise MigrationError("migration_schema_unsupported")
        version = int(row[0])
        digest = _digest(database)
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "source_version": version,
        "target_version": HISTORICAL_LEGS_SCHEMA_VERSION if version < 3 else version,
        "state_sha256": digest,
        "steps": (
            ["receipts_v2", "legs_v3"]
            if version == 1
            else ["legs_v3"]
            if version == 2
            else []
        ),
        "status": "already-current" if version >= 3 else "approval-required",
        "changes": (
            "Retain historical aliases and immutable retries for per-body receipts."
            if version < 3
            else "No schema transition; this preview does not certify semantic health."
        ),
    }
    body["plan_sha256"] = hashlib.sha256(canonical_bytes(body)).hexdigest()
    return body


def _sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, value: dict[str, Any]) -> None:
    data = canonical_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync(path.parent)


def _copy_database(source: Path, destination: Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    with (
        closing(_database(source)) as database,
        closing(sqlite3.connect(destination)) as target,
    ):
        database.backup(target)
    _sync(destination)
    _sync(destination.parent)


def _copy_anchor(source: Path, destination: Path) -> None:
    _file(source)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync(destination.parent)


def apply(
    store: CommunicationStore, backup: Path, expected_plan: str
) -> dict[str, Any]:
    """Caller retains the runtime lock and has stopped every other writer.

    Rehearse both upgrades on a private SQLite snapshot first. A durable journal
    records exactly the source, intermediate and target states before live DDL.
    """
    before = plan(store.ledger.path)
    if before["plan_sha256"] != expected_plan:
        raise MigrationError("migration_plan_changed")
    if not before["steps"]:
        return before
    if any(parent.is_symlink() for parent in backup.parents):
        raise MigrationError("migration_ancestor_symlink")
    backup.mkdir(mode=0o700)
    _sync(backup.parent)
    source = backup / "source.sqlite"
    rehearsal = backup / "rehearsal.sqlite"
    _copy_database(store.ledger.path, source)
    _copy_database(source, rehearsal)
    anchor = backup / "source.anchor"
    _copy_anchor(store.anchor_path, anchor)
    rehearsal_anchor = rehearsal.with_name(
        rehearsal.name + ".communication-anchor.json"
    )
    _copy_anchor(anchor, rehearsal_anchor)
    ledger = Ledger(
        rehearsal,
        authority=store.ledger.authority,
        local_origin=store.ledger.local_origin,
        clock=store.clock,
    )
    candidate = CommunicationStore(
        ledger,
        clock=store.clock,
        foreign_authority_resolver=store.foreign_authority_resolver,
    )
    select_persisted_schema(candidate, ledger)
    states = {str(before["source_version"]): before["state_sha256"]}
    if not candidate.receipts_v2:
        candidate.upgrade_receipts_v2()
        states["2"] = state_digest(rehearsal)
    candidate.upgrade_legs_v3()
    # Verify the same semantic invariants used by ordinary operations, not just
    # SQLite's structural integrity, before allowing live DDL.
    with candidate._database() as database:
        candidate._validate_store(database)
        candidate._validate_cached_histories(database)
        candidate._validate_conflicts(database)
    target_version = str(before["target_version"])
    if plan(rehearsal)["source_version"] != before["target_version"]:
        raise MigrationError("migration_target_schema_mismatch")
    states[target_version] = state_digest(rehearsal)
    if state_digest(source) != before["state_sha256"]:
        raise MigrationError("migration_snapshot_mismatch")
    journal = {
        "schema": SCHEMA,
        "plan": before,
        "allowed_states": states,
        "source_file_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "anchor_sha256": hashlib.sha256(anchor.read_bytes()).hexdigest(),
    }
    _write(backup / "prepared.json", journal)
    if plan(store.ledger.path) != before:
        raise MigrationError("migration_plan_changed")
    if store.anchor_path.read_bytes() != anchor.read_bytes():
        raise MigrationError("migration_anchor_changed")
    select_persisted_schema(store, store.ledger)
    if not store.receipts_v2:
        store.upgrade_receipts_v2()
    store.upgrade_legs_v3()
    after = plan(store.ledger.path)
    if (
        after["source_version"] != before["target_version"]
        or after["state_sha256"] != states[target_version]
    ):
        raise MigrationError("migration_result_mismatch")
    result = {
        "schema": SCHEMA,
        "status": "migrated",
        "source_version": before["source_version"],
        "target_version": before["target_version"],
        "state_sha256": after["state_sha256"],
        "source_plan_sha256": expected_plan,
    }
    _write(backup / "completed.json", result)
    return result


def recover(path: Path, backup: Path, expected_state: str) -> dict[str, Any]:
    """Restore only an exact prepared migration state, never subsequent work."""
    daemon._state_root(backup)
    journal_path = backup / "prepared.json"
    source = backup / "source.sqlite"
    anchor = backup / "source.anchor"
    for item in (journal_path, source, anchor):
        _file(item)
    journal = json.loads(journal_path.read_bytes())
    if journal.get("schema") != SCHEMA:
        raise MigrationError("migration_journal_invalid")
    if hashlib.sha256(source.read_bytes()).hexdigest() != journal["source_file_sha256"]:
        raise MigrationError("migration_snapshot_changed")
    if hashlib.sha256(anchor.read_bytes()).hexdigest() != journal["anchor_sha256"]:
        raise MigrationError("migration_snapshot_changed")
    current = state_digest(path)
    if current != expected_state or current not in journal["allowed_states"].values():
        raise MigrationError("migration_recovery_would_discard_work")
    live_anchor = path.with_name(path.name + ".communication-anchor.json")
    _file(live_anchor)
    if live_anchor.read_bytes() != anchor.read_bytes():
        raise MigrationError("migration_anchor_changed")
    _file(path)
    with (
        closing(_database(source)) as database,
        closing(sqlite3.connect(path)) as target,
    ):
        database.backup(target)
    _sync(path)
    restored = state_digest(path)
    if restored != journal["plan"]["state_sha256"]:
        raise MigrationError("migration_recovery_mismatch")
    return {
        "schema": SCHEMA,
        "status": "recovered",
        "state_sha256": restored,
        "source_version": journal["plan"]["source_version"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "recover"))
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--bundle", default="runtime.json")
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--expected-state-sha256")
    parser.add_argument("--password-fd", type=int)
    args = parser.parse_args(argv)
    lock: int | None = None
    try:
        root = daemon._state_root(args.state_root)
        if any(parent.is_symlink() for parent in root.parents):
            raise MigrationError("migration_ancestor_symlink")
        bundle_path = root / args.bundle
        if bundle_path.parent != root:
            raise MigrationError("migration_bundle_name_invalid")
        _file(bundle_path)
        bundle = json.loads(bundle_path.read_bytes())
        name = bundle["ledger"]
        if not isinstance(name, str) or Path(name).name != name:
            raise MigrationError("migration_ledger_name_invalid")
        path = root / name
        if args.command == "plan":
            result = plan(path)
        else:
            if args.backup_dir is None:
                raise MigrationError("migration_backup_required")
            try:
                lock = daemon.acquire_lock(root)
            except BlockingIOError as error:
                raise MigrationError("migration_runtime_running") from error
            if args.command == "recover":
                if args.expected_state_sha256 is None:
                    raise MigrationError("migration_state_approval_required")
                result = recover(path, args.backup_dir, args.expected_state_sha256)
            else:
                if args.expected_plan_sha256 is None:
                    raise MigrationError("migration_plan_approval_required")
                preview = plan(path)
                if preview["plan_sha256"] != args.expected_plan_sha256:
                    raise MigrationError("migration_plan_changed")
                if not preview["steps"]:
                    result = preview
                else:
                    if args.password_fd is None:
                        raise MigrationError("migration_password_required")
                    runtime = load_runtime(
                        root,
                        args.bundle,
                        daemon._password_reader(args.password_fd),
                        clock=lambda: time.time_ns() // 1_000_000,
                        egress=closed_visibility(
                            clock=lambda: time.time_ns() // 1_000_000,
                            catalog_mode="validate",
                        ),
                    )
                    store = runtime.service.communication
                    if store is None:
                        raise MigrationError("migration_communication_missing")
                    result = apply(store, args.backup_dir, args.expected_plan_sha256)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(
            "communication_migration_refused:" + daemon._safe_detail(error),
            file=sys.stderr,
        )
        return 1
    finally:
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    raise SystemExit(main())
