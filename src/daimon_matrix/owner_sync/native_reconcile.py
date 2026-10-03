"""Manual unsigned HMK reconciliation through native APIs; owner-private provenance.

Source labels describe existing pool lineages, never signed Matrix authorship.
Caller pins the native distribution and establishes approval, backup and writer
cutoff. Additive variants only: no deletion, implicit signed retraction or provider.
"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any, Protocol

from daimon_matrix.runtime import _owner_directory, _safe_file

PREFIX = "hmk-native-sync:v1:"


class NativeAPI(Protocol):
    DB_PATH: Path | str
    scan_content_for_secrets: Callable[[str], object] | None

    def normalize_text(self, text: str) -> str: ...
    def slugify(self, text: str) -> str: ...
    def simple_spr(self, text: str) -> str: ...
    def token_estimate(self, text: str) -> int: ...
    def add_text(
        self,
        shelf_name: str,
        title: str,
        raw: str,
        *,
        tags: list[str],
        importance: float,
        source_path: str,
        source_kind: str,
        replace: bool,
    ) -> int: ...
    def add_link(
        self, src_id: int, dst_id: int, link_type: str, *, weight: float, note: str
    ) -> Any: ...


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: (
            {"sqlite_blob_base64": base64.b64encode(item).decode()}
            if isinstance(item, bytes)
            else None
        ),
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def rows(path: Path | str) -> tuple[list[dict[str, Any]], set[int]]:
    with closing(
        sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        tables = {
            r[0]
            for r in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        protected = (
            {
                r[0]
                for r in connection.execute(
                    "SELECT chapter_id FROM daimon_projections WHERE "
                    "chapter_id IS NOT NULL"
                )
            }
            if "daimon_projections" in tables
            else set()
        )
        records = [
            dict(row)
            for row in connection.execute(
                "SELECT c.*,b.title AS book_title,b.slug AS "
                "book_slug,b.source_path AS "
                "book_source_path,b.source_kind AS "
                "book_source_kind,s.name AS shelf_name FROM chapters c "
                "JOIN books b ON b.id=c.book_id JOIN shelves s ON "
                "s.id=b.shelf_id ORDER BY c.id"
            )
        ]
        return records, {
            row["id"]
            for row in records
            if row["id"] in protected or row["book_source_kind"] == "daimon-projection"
        }


def native_history(path: Path | str) -> dict[str, list[str]]:
    tables = (
        "shelves",
        "books",
        "chapters",
        "chapter_links",
        "queries_log",
        "chapter_embeddings",
        "link_suggestions",
    )
    with closing(
        sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        return {
            name: sorted(
                digest(dict(row)) for row in connection.execute("SELECT * FROM " + name)
            )
            for name in tables
        }


def check_history(baseline: dict[str, list[str]], path: Path | str) -> None:
    current = native_history(path)
    for name, original in baseline.items():
        if not set(original).issubset(current[name]):
            raise ValueError("native_sync_history_changed:" + name)
        if (
            name in {"queries_log", "chapter_embeddings", "link_suggestions"}
            and original != current[name]
        ):
            raise ValueError("native_sync_unselected_history_changed:" + name)


def origin_key(label: str, row: dict[str, Any]) -> str:
    return digest(
        {"pool_lineage": label, "native_chapter_id": row["id"], "revision": row}
    )


def locator(row: dict[str, Any]) -> tuple[str, str, int, str]:
    return (row["shelf_name"], row["book_slug"], row["ordinal"], row["title"])


def empty_state() -> dict[str, Any]:
    return {
        "schema": "compaii.private-native-sync/v1",
        "origins": {},
        "bindings": {},
        "plans": {},
        "edges": {},
    }


def binding_key(label: str, origin: str) -> str:
    return label + ":" + origin


def persist(state: dict[str, Any], path: Path | str) -> None:
    path = Path(path).absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=path.exists())
    raw = canonical(state) + b"\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".native-sync-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_state(path: Path | str) -> dict[str, Any]:
    path = Path(path).absolute()
    _owner_directory(path.parent)
    _safe_file(path.parent, path.name, must_exist=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            state = json.load(stream)
    finally:
        os.close(descriptor)
    if (
        set(state) != {"schema", "origins", "bindings", "plans", "edges"}
        or state["schema"] != "compaii.private-native-sync/v1"
    ):
        raise ValueError("unsupported_native_sync_state")
    return dict(state)


def prepare(
    *,
    source_db: Path | str,
    target_db: Path | str,
    source_label: str,
    target_label: str,
    state: dict[str, Any],
) -> dict[str, Any]:
    if source_label == target_label:
        raise ValueError("distinct_pool_lineages_required")
    incoming, signed = rows(source_db)
    target, target_signed = rows(target_db)
    target_by_id = {row["id"]: row for row in target}
    entries = []
    source_mapping = {}
    for row in incoming:
        if row["id"] in signed:
            continue
        native_id = row["id"]
        matching = [
            (key[len(source_label) + 1 :], item)
            for key, item in state["bindings"].items()
            if key.startswith(source_label + ":") and item["chapter_id"] == row["id"]
        ]
        verified = [key for key, item in matching if item["record_hash"] == digest(row)]
        label = source_label
        managed = row["book_source_path"] and (
            row["book_source_path"].startswith(PREFIX)
            or (
                row["book_source_kind"] == "external-hmk-import"
                and row["book_source_path"].startswith("hmk-snapshot:")
            )
        )
        if managed and verified:
            # Re-export canonical unsigned provenance, not the generated retrieval row.
            inherited = state["origins"][verified[0]]
            row = inherited["original"]
            label = inherited["source_label"]
        elif (
            row["book_source_path"]
            and row["book_source_path"].startswith(PREFIX)
            and not matching
        ):
            raise ValueError("generated_import_provenance_missing")
        # Edited imports are new local variants; the old origin remains in state.
        key = origin_key(label, row)
        binding = state["bindings"].get(binding_key(target_label, key))
        if (
            binding
            and binding["chapter_id"] in target_by_id
            and binding["record_hash"] == digest(target_by_id[binding["chapter_id"]])
            and (
                not row.get("embed_disabled")
                or target_by_id[binding["chapter_id"]].get("embed_disabled")
            )
        ):
            action = "reuse"
            target_id = binding["chapter_id"]
        else:
            exact = [
                item
                for item in target
                if item["id"] not in target_signed
                and locator(item) == locator(row)
                and (item["raw"], item["spr"]) == (row["raw"], row["spr"])
                and (not row.get("embed_disabled") or item.get("embed_disabled"))
            ]
            if len(exact) > 1:
                raise ValueError("ambiguous_native_locator")
            action = "reuse" if exact else "import"
            target_id = exact[0]["id"] if exact else None
        if not isinstance(json.loads(row["tags_json"]), list):
            raise ValueError("invalid_native_tags")
        source_mapping[native_id] = key
        entries.append(
            {
                "origin_key": key,
                "source_label": label,
                "original": row,
                "action": action,
                "target_chapter_id": target_id,
            }
        )
    with closing(
        sqlite3.connect(Path(source_db).as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        links = [
            {
                "original": dict(link),
                "source_origin": source_mapping.get(link["src_chapter_id"]),
                "destination_origin": source_mapping.get(link["dst_chapter_id"]),
            }
            for link in connection.execute("SELECT * FROM chapter_links ORDER BY id")
        ]
    body = {
        "schema": "compaii.private-native-sync-plan/v1",
        "source_label": source_label,
        "target_label": target_label,
        "entries": entries,
        "links": links,
        "native_history": native_history(target_db),
        "baseline_rows": target,
        "protected_ids": sorted(target_signed),
    }
    return {**body, "plan_id": digest(body)}


def apply(
    *,
    plan: dict[str, Any],
    target_db: Path | str,
    api: NativeAPI,
    state_path: Path | str,
    after_native_effect: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Persist intent and recover uncertain native additions by source URI."""
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    if digest(body) != plan["plan_id"]:
        raise ValueError("native_sync_plan_integrity_failed")
    if Path(api.DB_PATH) != Path(target_db):
        raise ValueError("native_api_destination_mismatch")
    state = read_state(state_path)
    target_label = plan["target_label"]
    previous = state["plans"].get(plan["plan_id"])
    if previous is not None and previous["plan"] != plan:
        raise ValueError("native_sync_saved_plan_conflict")
    check_history(plan["native_history"], target_db)
    current, signed = rows(target_db)
    by_id = {row["id"]: row for row in current}
    # Existing native/signed rows must remain byte-equivalent before ANY effect,
    # including recovery. Imports append; they never repair by overwriting a row.
    for original in plan["baseline_rows"]:
        if by_id.get(original["id"]) != original:
            raise ValueError("native_sync_receiver_baseline_drift")
    if signed != set(plan["protected_ids"]):
        raise ValueError("native_sync_signed_set_drift")
    for entry in plan["entries"]:
        source = entry["original"]
        if entry["origin_key"] != origin_key(entry["source_label"], source):
            raise ValueError("native_sync_origin_revision_mismatch")
        if entry["action"] not in {"reuse", "import"}:
            raise ValueError("invalid_native_sync_action")
        if entry["action"] == "reuse":
            effect = by_id[entry["target_chapter_id"]]
            if effect["id"] in signed or effect["raw"] != source["raw"]:
                raise ValueError("native_sync_reuse_content_mismatch")
            if source.get("embed_disabled") and not effect.get("embed_disabled"):
                raise ValueError("native_embedding_policy_relaxation")
        else:
            if source["raw"] != api.normalize_text(source["raw"]):
                raise ValueError("native_import_would_normalize_source")
            disabled = source["book_source_kind"] in {"code", "config"} or (
                api.scan_content_for_secrets
                and api.scan_content_for_secrets(source["raw"])
            )
            if source.get("embed_disabled") and not disabled:
                raise ValueError("native_embedding_policy_unrepresentable")
    if previous is None:
        state["plans"][plan["plan_id"]] = {"plan": plan, "receipts": {}}
        persist(state, state_path)
    receipts = state["plans"][plan["plan_id"]]["receipts"]
    summaries = []
    for entry in plan["entries"]:
        key = entry["origin_key"]
        source = entry["original"]
        uri = PREFIX + key
        if key != origin_key(entry["source_label"], source):
            raise ValueError("native_sync_origin_revision_mismatch")
        expected_title = "Sync " + key + " " + source["title"]
        expected_tags = [
            *json.loads(source["tags_json"]),
            "legacy-sync",
            "source:" + entry["source_label"],
        ]
        if entry["action"] == "reuse":
            target_id = entry["target_chapter_id"]
            effect = by_id[target_id]
            if target_id in signed:
                raise ValueError("signed_row_not_generic_memory")
        else:
            now, now_signed = rows(target_db)
            candidates = [row for row in now if row["book_source_path"] == uri]
            if candidates:
                if len(candidates) != 1:
                    raise ValueError("ambiguous_native_import_effect")
                effect = candidates[0]
                target_id = effect["id"]
            else:
                if source["raw"] != api.normalize_text(source["raw"]):
                    raise ValueError("native_import_would_normalize_source")
                # A digest-prefixed title is unique, but refuse a pre-existing book
                # rather than let native upsert mutate unrelated receiver metadata.
                with closing(
                    sqlite3.connect(Path(target_db).as_uri() + "?mode=ro", uri=True)
                ) as lookup:
                    if lookup.execute(
                        "SELECT 1 FROM books b JOIN shelves s ON "
                        "s.id=b.shelf_id WHERE s.name=? AND b.slug=?",
                        (source["shelf_name"], api.slugify(expected_title)),
                    ).fetchone():
                        raise ValueError("native_import_book_collision")
                target_id = api.add_text(
                    source["shelf_name"],
                    expected_title,
                    source["raw"],
                    tags=expected_tags,
                    importance=source["importance"],
                    source_path=uri,
                    source_kind=source["book_source_kind"],
                    replace=False,
                )
                if after_native_effect is not None:
                    after_native_effect(key)
                effects, _ = rows(target_db)
                effect = next(row for row in effects if row["id"] == target_id)
            if (
                effect["shelf_name"],
                effect["book_source_kind"],
                effect["book_source_path"],
                effect["title"],
                effect["raw"],
                json.loads(effect["tags_json"]),
                effect["importance"],
                effect["spr"],
                effect["tokens"],
            ) != (
                source["shelf_name"],
                source["book_source_kind"],
                uri,
                expected_title,
                source["raw"],
                expected_tags,
                source["importance"],
                api.simple_spr(source["raw"]),
                api.token_estimate(source["raw"]),
            ):
                raise ValueError("native_import_effect_mismatch")
            if source.get("embed_disabled") and not effect.get("embed_disabled"):
                raise ValueError("native_embedding_policy_relaxation")
            if target_id in now_signed:
                raise ValueError("signed_row_not_generic_memory")
        receipt = {"chapter_id": target_id, "record_hash": digest(effect)}
        if key in receipts and receipts[key] != receipt:
            raise ValueError("native_sync_receipt_drift")
        state["origins"][key] = {
            "source_label": entry["source_label"],
            "original": source,
        }
        state["bindings"][binding_key(target_label, key)] = receipt
        receipts[key] = receipt
        persist(state, state_path)
        summaries.append(
            {
                "origin_key": key,
                "target_chapter_id": target_id,
                "action": entry["action"],
            }
        )
    for edge in plan["links"]:
        original = edge["original"]
        src = edge["source_origin"]
        dst = edge["destination_origin"]
        edge_key = digest({"source_label": plan["source_label"], "original": original})
        if src is None or dst is None:
            status = "signed-or-missing-endpoint-retained"
        else:
            src_id = receipts[src]["chapter_id"]
            dst_id = receipts[dst]["chapter_id"]
            with closing(
                sqlite3.connect(Path(target_db).as_uri() + "?mode=ro", uri=True)
            ) as connection:
                connection.row_factory = sqlite3.Row
                existing = connection.execute(
                    "SELECT * FROM chapter_links WHERE src_chapter_id=? AND "
                    "dst_chapter_id=? AND link_type=?",
                    (src_id, dst_id, original["link_type"]),
                ).fetchall()
            if len(existing) > 1:
                raise ValueError("ambiguous_native_edge")
            if existing:
                status = (
                    "existing-edge-preserved"
                    if (existing[0]["weight"], existing[0]["note"])
                    == (original["weight"], original["note"])
                    else "conflicting-edge-retained-in-provenance"
                )
            else:
                api.add_link(
                    src_id,
                    dst_id,
                    original["link_type"],
                    weight=original["weight"],
                    note=original["note"],
                )
                status = "native-edge-added"
        state["edges"][edge_key] = {
            "source_label": plan["source_label"],
            "original": original,
            "state": status,
        }
        persist(state, state_path)
    check_history(plan["native_history"], target_db)
    return summaries


def seed_candidate(
    *,
    state: dict[str, Any],
    target_db: Path | str,
    target_label: str,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    """Reuse original candidate mappings without copying canonical projection rows."""
    target, signed = rows(target_db)
    by_id = {row["id"]: row for row in target}
    for item in provenance["chapters"]:
        key = origin_key(item["source"], item["original"])
        target_id = item["target_chapter_id"]
        if target_id in signed:
            raise ValueError("signed_row_not_generic_memory")
        effect = by_id[target_id]
        if effect["raw"] != item["original"]["raw"]:
            raise ValueError("legacy_seed_content_mismatch")
        state["origins"][key] = {
            "source_label": item["source"],
            "original": item["original"],
        }
        state["bindings"][binding_key(target_label, key)] = {
            "chapter_id": target_id,
            "record_hash": digest(effect),
        }
    return state
