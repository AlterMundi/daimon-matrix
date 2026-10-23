"""Private, read-only discovery for human-directed same-being delta integration.

Reuse export_being's path/content checks. This describes candidate sources and
known baselines; it does not export credentials, load a harness, claim adoption,
or infer that saving configuration changes a running conversation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any

from tools import export_being

SCHEMA = "dm.behavior-inventory/v1"
LIMIT = 4 * 1024 * 1024
PRIVATE_KEY = re.compile(
    r"(?:^|[_-])(?:token|secret|password|credential|api[_-]?key|authorization)$",
    re.I,
)


def hashed(value: Any) -> str:
    return hashlib.sha256(export_being.json_bytes(value)).hexdigest()


def describe_file(path: Path) -> dict[str, Any]:
    """Never follow an unresolved alias or include file contents in the report."""
    row: dict[str, Any] = {"path": str(path)}
    try:
        export_being.safe_path(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return dict(row, state="unsupported_file_type")
        if info.st_size > LIMIT:
            return dict(row, state="content_exceeds_discovery_budget")
        export_being.scan_credentials(path)
        raw = path.read_bytes()
        if len(raw) > LIMIT or path.stat().st_mtime_ns != info.st_mtime_ns:
            return dict(row, state="concurrent_change")
        return dict(
            row,
            state="observed",
            bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except FileNotFoundError:
        return dict(row, state="absent")
    except PermissionError:
        return dict(row, state="unavailable")
    except export_being.ExportError:
        return dict(row, state="private_or_unresolved_source")


def leaves(value: Any, prefix: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, item in sorted(value.items()):
            yield from leaves(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, (*prefix, str(index)))
    else:
        yield prefix, value


def references(value: Any, *, home: Path) -> list[Path]:
    """Literal paths only; never evaluate shell, environment or peer content."""
    if not isinstance(value, str):
        return []
    if value.startswith("~/"):
        return [home / value[2:]]
    if value.startswith("/") and "\n" not in value and "\x00" not in value:
        return [Path(value)]
    return []


def configuration(path: Path, *, home: Path, defaults: dict | None = None) -> dict:
    row = describe_file(path)
    if row["state"] != "observed":
        # The config can mix useful behavior and credentials. Parse privately;
        # do not discard the surrounding behavior or export the raw config.
        if row["state"] != "private_or_unresolved_source":
            return dict(row, settings=[], references=[])
        try:
            export_being.safe_path(path)
        except export_being.ExportError:
            return dict(row, settings=[], references=[])
    try:
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            return dict(
                row,
                state="content_exceeds_discovery_budget",
                settings=[],
                references=[],
            )
        value = tomllib.loads(raw.decode())
    except (OSError, ValueError, UnicodeError):
        return dict(row, state="configuration_unreadable", settings=[], references=[])
    expected = dict(leaves(defaults)) if defaults is not None else {}
    settings, found = [], set()
    for key, item in leaves(value):
        if any(PRIVATE_KEY.search(part) for part in key):
            settings.append(dict(key=list(key), state="private_binding_omitted"))
            continue
        fingerprint = hashed(item)
        baseline = expected.get(key)
        known = key in expected
        settings.append(
            dict(
                key=list(key),
                value_sha256=fingerprint,
                baseline_state=(
                    "inherited"
                    if known and type(item) is type(baseline) and item == baseline
                    else "modified"
                    if known
                    else "unknown_default"
                ),
            )
        )
        found.update(references(item, home=home))
    return dict(
        row, settings=settings, references=[describe_file(p) for p in sorted(found)]
    )


def discover(
    *,
    home: Path,
    codex_home: Path,
    cwd: Path,
    version: str,
    source_revision: str,
    source_evidence: Path,
    defaults: Path | None = None,
    additional: list[Path] | None = None,
    native_config: Path | None = None,
    native_baseline: Path | None = None,
    origin: Path | None = None,
) -> dict:
    for path in (home, codex_home, cwd, source_evidence):
        export_being.safe_path(path)
    evidence = describe_file(source_evidence)
    if evidence["state"] != "observed" or not re.fullmatch(
        r"[0-9a-f]{40}", source_revision
    ):
        raise ValueError("exact_harness_source_evidence_required")
    default_values = None
    baseline = {
        "state": "unknown",
        "reason": "no_qualified_effective_default_configuration",
    }
    if defaults is not None:
        baseline = describe_file(defaults)
        if baseline["state"] != "observed":
            raise ValueError("qualified_default_configuration_required")
        default_values = tomllib.loads(defaults.read_text())
    configs = [
        configuration(codex_home / "config.toml", home=home, defaults=default_values)
    ]
    instructions = []
    # Exact global override/fallback precedence. Project candidates remain
    # candidates until native evidence confirms trust, selection and truncation.
    for filename in ("AGENTS.override.md", "AGENTS.md"):
        row = describe_file(codex_home / filename)
        instructions.append(dict(row, scope="global"))
        if row["state"] == "observed" and (codex_home / filename).read_text().strip():
            break
        if row["state"] not in ("observed", "absent"):
            break  # Do not silently fall back after an unreadable override.
    for directory in reversed((cwd, *cwd.parents)):
        for filename in ("AGENTS.override.md", "AGENTS.md"):
            row = describe_file(directory / filename)
            if row["state"] != "absent":
                instructions.append(dict(row, scope="project_candidate"))
        config = directory / ".codex/config.toml"
        if config != codex_home / "config.toml" and config.exists():
            configs.append(configuration(config, home=home, defaults=default_values))
    skills = []
    for root in (home / ".agents/skills", codex_home / "skills"):
        if not root.exists():
            skills.append(dict(path=str(root), state="absent"))
            continue
        files, omissions = export_being.inventory(root, "skills")
        selected = [
            f
            for f in files
            if Path(f["path"]).name in ("SKILL.md", "package.json", "openai.yaml")
        ]
        skills.append(
            dict(
                path=str(root),
                state="candidate_discovery_root",
                documents=[describe_file(root / f["path"]) for f in selected],
                omissions=omissions,
            )
        )
    native = native_comparison(native_config, native_baseline)
    attribution = {"state": "unassigned"}
    if origin is not None:
        export_being.safe_path(origin)
        owner = json.loads(origin.read_text())
        local = owner["local_origin"]
        attribution = dict(
            state="receiving_owner_observation",
            being_ref=owner["being_ref"],
            **{
                key: local[key]
                for key in ("body_ref", "embodiment_id", "incarnation_id")
            },
            evidence=describe_file(origin),
        )
    return dict(
        schema=SCHEMA,
        origin=attribution,
        receiving=dict(home=str(home), codex_home=str(codex_home), cwd=str(cwd)),
        harness=dict(
            name="codex",
            version=version,
            source_revision=source_revision,
            source_evidence=evidence,
        ),
        baseline=baseline,
        configuration=configs,
        native_configuration=native,
        instructions=instructions,
        skills=skills,
        additional_sources=[describe_file(p) for p in additional or []],
        gaps=[
            "native_effective_layers_and_running_session_consumption_unverified",
            "launch_overrides_managed_policy_and_environment_require_receiving_evidence",
            "plugins_hooks_and_indirect_text_references_require_selected_content_closure",
        ],
        authority=(
            "unsigned receiving-local observation; no historical native event invented"
        ),
        effects=dict(
            configuration_changed=False, model_started=False, memory_imported=False
        ),
    )


def native_comparison(current: Path | None, baseline: Path | None) -> dict:
    """Compare retained native reads; null is unspecified, never a factory value."""
    if current is None:
        return dict(state="unobserved")
    export_being.safe_path(current)
    observed = json.loads(current.read_text())
    previous = None
    if baseline is not None:
        export_being.safe_path(baseline)
        previous = json.loads(baseline.read_text())
        if observed["binary_sha256"] != previous["binary_sha256"]:
            raise ValueError("matching_native_binary_baseline_required")
    defaults = dict(leaves(previous["result"]["config"])) if previous else {}
    settings = []
    for key, value in leaves(observed["result"]["config"]):
        if any(PRIVATE_KEY.search(part) for part in key):
            settings.append(dict(key=list(key), state="private_binding_omitted"))
            continue
        before = defaults.get(key)
        state = (
            "unknown_default"
            if key not in defaults
            else "baseline_unspecified"
            if before is None and value is not None
            else "inherited"
            if type(before) is type(value) and before == value
            else "modified"
        )
        settings.append(
            dict(key=list(key), value_sha256=hashed(value), baseline_state=state)
        )
    layers = [
        dict(
            source=item.get("name", item.get("source")),
            version=item.get("version"),
            disabled_reason=item.get("disabledReason"),
        )
        for item in observed["result"].get("layers", [])
    ]
    return dict(
        state="native_read_observed",
        current=describe_file(current),
        baseline=describe_file(baseline) if baseline else None,
        layers=layers,
        settings=settings,
        running_turn_consumption="unverified",
    )


def comparable_items(inventory: dict) -> dict[tuple[str, ...], str]:
    """Exact content identity only; local path hashes are not semantic conflicts."""
    items = {}
    for row in inventory.get("native_configuration", {}).get("settings", []):
        if "value_sha256" in row:
            items[("native-setting", *row["key"])] = row["value_sha256"]
    for row in inventory["instructions"]:
        if row["scope"] == "global" and row["state"] == "observed":
            items[("global-instructions",)] = row["sha256"]
    for index, root in enumerate(inventory["skills"]):
        for row in root.get("documents", []):
            if row["state"] == "observed":
                relative = Path(row["path"]).relative_to(root["path"]).as_posix()
                items[("skill-document", str(index), relative)] = row["sha256"]
    return items


def compare(left: dict, right: dict, common: dict | None = None) -> dict:
    """A preview never resolves divergent manual edits or applies peer content."""
    for value in (left, right, *([common] if common is not None else [])):
        if value.get("schema") != SCHEMA or not value.get("origin", {}).get(
            "being_ref"
        ):
            raise ValueError("attributed_receiving_inventory_required")
        if value["origin"]["being_ref"] != left["origin"]["being_ref"]:
            raise ValueError("same_being_inventory_required")
    local = comparable_items(left)
    incoming = comparable_items(right)
    baseline = comparable_items(common) if common is not None else {}
    rows = []
    for key in sorted(local.keys() | incoming.keys()):
        before = baseline.get(key)
        a, b = local.get(key), incoming.get(key)
        state = (
            "equal"
            if a == b
            else "different_without_common_history"
            if key not in baseline
            else "incoming_changed"
            if a == before
            else "local_changed"
            if b == before
            else "conflicting_edits"
        )
        rows.append(
            dict(
                item=list(key),
                state=state,
                local_sha256=a,
                incoming_sha256=b,
                common_sha256=before,
            )
        )
    return dict(
        schema="dm.behavior-comparison/v1",
        being_ref=left["origin"]["being_ref"],
        inventories=dict(
            local=hashed(left),
            incoming=hashed(right),
            common=hashed(common) if common is not None else None,
        ),
        entries=rows,
        gaps=sorted(set(left["gaps"] + right["gaps"])),
        meaning=(
            "exact content preview; differences require "
            "local intent/adaptation decisions"
        ),
        effects=dict(configuration_changed=False, adoption_authored=False),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-evidence", type=Path, required=True)
    parser.add_argument("--defaults", type=Path)
    parser.add_argument("--additional", type=Path, action="append", default=[])
    parser.add_argument("--native-config", type=Path)
    parser.add_argument("--native-baseline", type=Path)
    parser.add_argument("--origin", type=Path)
    parser.add_argument("--compare-with", type=Path)
    parser.add_argument("--common", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = discover(
        home=args.home,
        codex_home=args.codex_home,
        cwd=args.cwd,
        version=args.version,
        source_revision=args.source_revision,
        source_evidence=args.source_evidence,
        defaults=args.defaults,
        additional=args.additional,
        native_config=args.native_config,
        native_baseline=args.native_baseline,
        origin=args.origin,
    )
    if args.compare_with is not None:
        export_being.safe_path(args.compare_with)
        common = None
        if args.common is not None:
            export_being.safe_path(args.common)
            common = json.loads(args.common.read_text())
        result = compare(result, json.loads(args.compare_with.read_text()), common)
    export_being.new_file(args.output, export_being.json_bytes(result))
    print(
        json.dumps(
            dict(
                schema=result["schema"],
                output_written=True,
                inventory_sha256=hashed(result),
                effects=result["effects"],
            )
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
