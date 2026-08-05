#!/usr/bin/env python3
"""Generate deterministic DM-042 local-We schema and public vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import b64url  # noqa: E402
from daimon_matrix.local_we import (  # noqa: E402
    MAX_SYNC_RECEIPTS,
    REPORT_SCHEMA,
    _report_id,
    validate_local_we_report,
)

HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
DERIVED = {
    "type": "string",
    "pattern": "^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$",
}
UUID = {"type": "string", "format": "uuid"}
UINT = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}
EMBODIMENT = {
    "type": "string",
    "pattern": "^embodiment:[A-Za-z0-9._:-]{1,240}$",
}
INCARNATION = {
    "type": "string",
    "pattern": "^incarnation:[A-Za-z0-9._:-]{1,240}$",
}


def closed(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def body_schema(
    harness: str, decision: str, state: str, launch_prefix: str
) -> dict[str, Any]:
    return closed(
        {
            "harness": {"const": harness},
            "body_ref": {"type": "string", "minLength": 1, "maxLength": 256},
            "embodiment_id": EMBODIMENT,
            "incarnation_id": INCARNATION,
            "principal_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "embodiment_credential_id": DERIVED,
            "incarnation_authorization_id": DERIVED,
            "signing_key_id": DERIVED,
            "encryption_key_id": DERIVED,
            "transport_key_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 32,
                "uniqueItems": True,
                "items": DERIVED,
            },
            "matrix_session_id": DERIVED,
            "matrix_high_water": HASH,
            "capability_set_hash": HASH,
            "profile_id": DERIVED,
            "launch_receipt_id": {
                "type": "string",
                "pattern": f"^{launch_prefix}[A-Za-z0-9_-]{{43}}$",
            },
            "ledger_heads_hash": HASH,
            "ledger_state_hash": HASH,
            "projection_hash": HASH,
            "decision": {"const": decision},
            "decision_event_id": UUID,
            "state": {"const": state},
            "remote_decision_event_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 32,
                "uniqueItems": True,
                "items": UUID,
            },
        }
    )


def validation_schema() -> dict[str, Any]:
    isolation = closed(
        {
            name: {"const": True}
            for name in (
                "capability_sets_distinct",
                "credentials_distinct",
                "encryption_keys_distinct",
                "incarnations_distinct",
                "ledger_files_distinct",
                "matrix_sessions_distinct",
                "principals_distinct",
                "profile_roots_distinct",
                "signing_keys_distinct",
                "transport_keys_distinct",
            )
        }
    )
    sync = closed(
        {
            "sender_embodiment_id": EMBODIMENT,
            "receiver_embodiment_id": EMBODIMENT,
            "request_id": UUID,
            "page_hash": HASH,
            "receipt_hash": HASH,
            "received": UINT,
            "inserted": UINT,
            "replayed": UINT,
        }
    )
    schema = closed(
        {
            "schema": {"const": REPORT_SCHEMA},
            "being_ref": {
                "type": "string",
                "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
            },
            "control_head": {
                "type": "string",
                "pattern": "^dm:identity:v1:[A-Za-z0-9_-]{43}$",
            },
            "manifest_hash": HASH,
            "observed_at_ms": UINT,
            "bodies": {
                "type": "array",
                "prefixItems": [
                    body_schema(
                        "codex",
                        "adopt",
                        "adopted",
                        "dm:codex-launch-receipt:v1:",
                    ),
                    body_schema("hermes", "reject", "rejected", "dm:hermes-launch:v1:"),
                ],
                "minItems": 2,
                "maxItems": 2,
            },
            "sync": {
                "type": "array",
                "minItems": 2,
                "maxItems": MAX_SYNC_RECEIPTS,
                "items": sync,
            },
            "event_set_hash": HASH,
            "target_event_id": UUID,
            "storage_isolation": isolation,
            "report_id": {
                "type": "string",
                "pattern": "^dm:local-we-validation:v1:[A-Za-z0-9_-]{43}$",
            },
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://daimon.local/schemas/local-we/v1/validation.schema.json",
        "title": "Daimon Matrix local plural-body validation v1",
        **schema,
    }


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def body(
    *,
    harness: str,
    label: str,
    decision: str,
    state: str,
    decision_event_id: str,
    remote_decision_event_id: str,
    shared_heads: str,
    shared_state: str,
    shared_high_water: str,
) -> dict[str, Any]:
    launch_kind = "codex-launch-receipt" if harness == "codex" else "hermes-launch"
    return {
        "harness": harness,
        "body_ref": f"cluster:{label}:compaii",
        "embodiment_id": f"embodiment:{label}",
        "incarnation_id": f"incarnation:{label}:0",
        "principal_id": f"compaii@{label}",
        "embodiment_credential_id": derived("credential", f"{label}-credential"),
        "incarnation_authorization_id": derived(
            "authorization", f"{label}-authorization"
        ),
        "signing_key_id": derived("key", f"{label}-signing"),
        "encryption_key_id": derived("key", f"{label}-encryption"),
        "transport_key_ids": [derived("key", f"{label}-transport")],
        "matrix_session_id": derived("session", f"{label}-matrix-session"),
        "matrix_high_water": shared_high_water,
        "capability_set_hash": digest(f"{label}-capabilities"),
        "profile_id": derived(f"{harness}-profile", f"{label}-profile"),
        "launch_receipt_id": derived(launch_kind, f"{label}-launch"),
        "ledger_heads_hash": shared_heads,
        "ledger_state_hash": shared_state,
        "projection_hash": digest(f"{label}-projection"),
        "decision": decision,
        "decision_event_id": decision_event_id,
        "state": state,
        "remote_decision_event_ids": [remote_decision_event_id],
    }


def valid_report() -> dict[str, Any]:
    codex_decision = "42000000-0000-4000-8000-000000000003"
    hermes_decision = "42000000-0000-4000-8000-000000000004"
    heads = digest("dm042-converged-heads")
    state = digest("dm042-converged-state")
    high_water = digest("dm042-initial-high-water")
    core = {
        "schema": REPORT_SCHEMA,
        "being_ref": derived("being", "dm042-being"),
        "control_head": derived("identity", "dm042-control-head"),
        "manifest_hash": digest("dm042-manifest"),
        "observed_at_ms": 1_800_000_000_002,
        "bodies": [
            body(
                harness="codex",
                label="legion",
                decision="adopt",
                state="adopted",
                decision_event_id=codex_decision,
                remote_decision_event_id=hermes_decision,
                shared_heads=heads,
                shared_state=state,
                shared_high_water=high_water,
            ),
            body(
                harness="hermes",
                label="daimonmatrix",
                decision="reject",
                state="rejected",
                decision_event_id=hermes_decision,
                remote_decision_event_id=codex_decision,
                shared_heads=heads,
                shared_state=state,
                shared_high_water=high_water,
            ),
        ],
        "sync": sorted(
            [
                {
                    "sender_embodiment_id": "embodiment:legion",
                    "receiver_embodiment_id": "embodiment:daimonmatrix",
                    "request_id": "42000000-0000-4000-8000-000000000011",
                    "page_hash": digest("dm042-page-codex-hermes"),
                    "receipt_hash": digest("dm042-receipt-codex-hermes"),
                    "received": 2,
                    "inserted": 2,
                    "replayed": 0,
                },
                {
                    "sender_embodiment_id": "embodiment:daimonmatrix",
                    "receiver_embodiment_id": "embodiment:legion",
                    "request_id": "42000000-0000-4000-8000-000000000012",
                    "page_hash": digest("dm042-page-hermes-codex"),
                    "receipt_hash": digest("dm042-receipt-hermes-codex"),
                    "received": 2,
                    "inserted": 2,
                    "replayed": 0,
                },
            ],
            key=lambda item: (
                item["sender_embodiment_id"],
                item["receiver_embodiment_id"],
                item["request_id"],
            ),
        ),
        "event_set_hash": state,
        "target_event_id": "42000000-0000-4000-8000-000000000001",
        "storage_isolation": {
            "capability_sets_distinct": True,
            "credentials_distinct": True,
            "encryption_keys_distinct": True,
            "incarnations_distinct": True,
            "ledger_files_distinct": True,
            "matrix_sessions_distinct": True,
            "principals_distinct": True,
            "profile_roots_distinct": True,
            "signing_keys_distinct": True,
            "transport_keys_distinct": True,
        },
    }
    return validate_local_we_report({**core, "report_id": _report_id(core)})


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, ensure_ascii=False).encode() + b"\n"


def outputs() -> dict[Path, bytes]:
    valid = valid_report()
    wrong_id = copy.deepcopy(valid)
    wrong_id["report_id"] = derived("local-we-validation", "wrong-report")
    aliased = copy.deepcopy(valid)
    aliased["bodies"][1]["capability_set_hash"] = aliased["bodies"][0][
        "capability_set_hash"
    ]
    false_isolation = copy.deepcopy(valid)
    false_isolation["storage_isolation"]["ledger_files_distinct"] = False
    vectors = {
        "valid/report.json": valid,
        "negative/report-id-tampered.json": wrong_id,
        "negative/body-identity-aliased.json": aliased,
        "negative/storage-isolation-false.json": false_isolation,
    }
    vector_root = ROOT / "vectors/local-we/v1"
    result = {
        ROOT / "schemas/local-we/v1/validation.schema.json": json_bytes(
            validation_schema()
        )
    }
    for relative, value in vectors.items():
        result[vector_root / relative] = json_bytes(value)
    result[vector_root / "index.json"] = json_bytes(
        {
            "schema": "dm.local-we.vector-index/v1",
            "files": [
                {
                    "name": relative,
                    "sha256": hashlib.sha256(json_bytes(value)).hexdigest(),
                    "valid": relative.startswith("valid/"),
                }
                for relative, value in sorted(vectors.items())
            ],
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = outputs()
    if args.check:
        drift = [
            os.fspath(path.relative_to(ROOT))
            for path, raw in expected.items()
            if not path.exists() or path.read_bytes() != raw
        ]
        if drift:
            print(
                "DM-042 generated artifact drift: " + ", ".join(drift), file=sys.stderr
            )
            return 1
        return 0
    for path, raw in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
