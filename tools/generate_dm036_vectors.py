#!/usr/bin/env python3
"""Generate deterministic DM-036 collective-memory interop vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import daimon_matrix.collective_memory as collective  # noqa: E402
from daimon_matrix.canonical import canonical_bytes  # noqa: E402

DEFAULT_OUTPUT = ROOT / "vectors" / "collective-memory" / "v1"
UPSTREAM_ROOT = Path(
    os.environ.get(
        "COLLECTIVE_MEMORY_CONTRACT_ROOT", str(ROOT.parent / "collective-memory")
    )
).resolve()
UPSTREAM = UPSTREAM_ROOT / "vectors" / "exchange" / "v1"
NOW = 1_800_000_000_000
IMPORT_EVENT = "36000000-0000-4000-8000-000000000001"
REQUEST_EVENT = "36000000-0000-4000-8000-000000000002"


def read(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((UPSTREAM / name).read_bytes()))


def objects() -> dict[str, dict[str, Any]]:
    manifest = collective.validate_export_manifest(read("export-manifest.json"))
    source_core = {
        "manifest": manifest,
        "content_bindings": [
            {
                "artifact_id": item["artifact_id"],
                "content_hash": item["content_hash"],
                "content_length": item["content_length"],
                "state": item["state"],
            }
            for item in manifest["body"]["artifacts"]
        ],
    }
    source_preview: dict[str, Any] = {
        "schema": collective.SOURCE_PREVIEW_SCHEMA,
        "preview_id": collective._derived(
            "dm:collective-source-preview:v1:",
            collective.SOURCE_PREVIEW_DOMAIN,
            source_core,
        ),
        "preview_hash": hashlib.sha256(canonical_bytes(source_core)).hexdigest(),
        **source_core,
    }
    source_preview = collective.validate_source_preview(source_preview)
    source_receipt = collective._source_receipt(
        manifest,
        preview_id=source_preview["preview_id"],
        preview_hash=source_preview["preview_hash"],
        source_log_hash="4" * 64,
        import_event_id=IMPORT_EVENT,
        imported_at_ms=NOW,
    )
    source_receipt = collective.validate_source_receipt(source_receipt)

    upstream_request = read("publication-request.json")
    upstream_preview = read("publication-preview.json")
    upstream_plan = read("publication-plan.json")
    upstream_receipt = read("publication-receipt.json")
    upstream_reconciliation = read("publication-reconciliation.json")
    consent_hash = hashlib.sha256(
        canonical_bytes(upstream_request["consent"])
    ).hexdigest()
    review_hash = hashlib.sha256(
        canonical_bytes(upstream_request["review"])
    ).hexdigest()
    request_id = "dm:collective-publisher-operation:v1:" + "A" * 43
    publisher_request = collective._request_summary(
        upstream_request,
        upstream_preview,
        upstream_plan,
        request_id=request_id,
        consent_hash=consent_hash,
        review_hash=review_hash,
        requested_at_ms=NOW,
    )
    publisher_request = collective.validate_publisher_request_payload(publisher_request)
    publisher_acceptance = collective._publisher_acceptance(
        publisher_request,
        upstream_receipt,
        upstream_reconciliation,
        request_event_id=REQUEST_EVENT,
        request_event_hash="5" * 64,
        accepted_at_ms=NOW,
    )
    publisher_acceptance = collective.validate_publisher_acceptance_payload(
        publisher_acceptance
    )
    negative = dict(source_receipt)
    negative["host_path"] = "/tmp/forbidden"
    return {
        "source-profile.json": collective.create_source_profile(
            producer_instance="collective:vector",
            producer_release="collective:release:vector",
            policy_version="policy:v1",
            scope_id="public",
        ),
        "source-preview.json": source_preview,
        "source-receipt.json": source_receipt,
        "publisher-profile.json": collective.create_publisher_profile(
            requester_id="operator:matrix-vector",
            policy_version="policy:v1",
            target_ids=["collective:article:vector"],
        ),
        "publisher-request.json": publisher_request,
        "publisher-acceptance.json": publisher_acceptance,
        "negative-host-path.json": negative,
    }


def write(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for name, value in sorted(objects().items()):
        raw = canonical_bytes(value) + b"\n"
        (output / name).write_bytes(raw)
        entries.append(
            {
                "name": name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "expect": "reject" if name.startswith("negative-") else "accept",
            }
        )
    index = {
        "schema": "dm.collective-memory.vector-index/v1",
        "upstream_commit": collective.COLLECTIVE_MEMORY_COMMIT,
        "upstream_schema_sha256": collective.COLLECTIVE_SCHEMA_SHA256,
        "files": entries,
    }
    (output / "index.json").write_bytes(canonical_bytes(index) + b"\n")


def check(output: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="dm036-vectors-") as directory:
        expected = Path(directory)
        write(expected)
        current = sorted(path.name for path in output.glob("*.json"))
        generated = sorted(path.name for path in expected.glob("*.json"))
        return current == generated and all(
            (output / name).read_bytes() == (expected / name).read_bytes()
            for name in generated
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.check:
        return 0 if check(arguments.output) else 1
    write(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
