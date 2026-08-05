#!/usr/bin/env python3
"""Generate DM-070 schema, deterministic fixture, and negative vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.multihost import (  # noqa: E402
    RECEIPT_SCHEMA,
    SCHEDULE,
    validate_multihost_receipt,
)
from daimon_matrix.synthetic_multihost import run_synthetic_multihost  # noqa: E402

FIXTURE = ROOT / "conformance/fixtures/dm070-multihost.json"
PROVENANCE = ROOT / "provenance/daimon-cluster-v1.json"
VECTOR_ROOT = ROOT / "vectors/multihost/v1"
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
COMMIT = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
UUID = {"type": "string", "format": "uuid"}
DERIVED = {
    "type": "string",
    "pattern": "^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$",
}
UINT = {"type": "integer", "minimum": 0, "maximum": 2**53 - 1}


def closed(properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def receipt_schema() -> dict[str, Any]:
    origin = closed(
        {
            "label": {"enum": ["legion", "daimonmatrix"]},
            "body_ref": {"type": "string", "minLength": 1, "maxLength": 256},
            "embodiment_id": {
                "type": "string",
                "pattern": "^embodiment:[A-Za-z0-9._:-]{1,240}$",
            },
            "initial_incarnation_id": {
                "type": "string",
                "pattern": "^incarnation:[A-Za-z0-9._:-]{1,240}$",
            },
            "current_incarnation_id": {
                "type": "string",
                "pattern": "^incarnation:[A-Za-z0-9._:-]{1,240}$",
            },
            "credential_id": DERIVED,
            "signing_key_id": DERIVED,
            "encryption_key_id": DERIVED,
            "transport_key_id": DERIVED,
            "capability_id": DERIVED,
            "state_fingerprint": HASH,
        }
    )
    direction = closed(
        {
            "receiver_embodiment_id": {
                "type": "string",
                "pattern": "^embodiment:[A-Za-z0-9._:-]{1,240}$",
            },
            "sender_embodiment_id": {
                "type": "string",
                "pattern": "^embodiment:[A-Za-z0-9._:-]{1,240}$",
            },
            "request_hashes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": HASH,
            },
            "page_hashes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": HASH,
            },
            "receipt_hashes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 256,
                "uniqueItems": True,
                "items": HASH,
            },
            "pages": UINT,
        }
    )
    interruption = closed(
        {
            "boundary": {"enum": ["after-receiver-commit", "before-receiver-commit"]},
            "request_hash": HASH,
            "page_hash": HASH,
            "receipt_hash": HASH,
            "process_restarted": {"const": True},
            "exact_replay": {"const": True},
        }
    )
    isolation_fields = (
        "state_roots_distinct",
        "ledger_inodes_distinct",
        "keystore_inodes_distinct",
        "capabilities_distinct",
        "signing_keys_distinct",
        "encryption_keys_distinct",
        "transport_principals_distinct",
        "request_journals_distinct",
        "no_shared_writable_state",
        "public_receipt_path_free",
        "public_receipt_secret_free",
        "no_live_host_mutation",
        "no_winner_election",
    )
    root = closed(
        {
            "schema": {"const": RECEIPT_SCHEMA},
            "run_profile": {"const": "installed-isolated-loopback/v1"},
            "source_commit": COMMIT,
            "package": closed(
                {
                    "name": {"const": "daimon-matrix"},
                    "version": {"const": "0.0.0"},
                    "entrypoint": {"const": "daimon-synthetic-multihost"},
                }
            ),
            "authority": closed(
                {
                    "being_ref": {
                        "type": "string",
                        "pattern": "^dm:being:v1:[A-Za-z0-9_-]{43}$",
                    },
                    "control_head": {
                        "type": "string",
                        "pattern": "^dm:identity:v1:[A-Za-z0-9_-]{43}$",
                    },
                    "initial_manifest_hash": HASH,
                    "successor_manifest_hash": HASH,
                    "embodiments": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": origin,
                    },
                }
            ),
            "processes": closed(
                {
                    "daemon_count": {"const": 2},
                    "simultaneously_awake": {"const": True},
                    "me_response_hashes": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": HASH,
                    },
                    "we_response_hashes": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": HASH,
                    },
                    "restart_count": UINT,
                    "fixed_test_clock_ms": UINT,
                }
            ),
            "partition": closed(
                {
                    "failed_request_id": UUID,
                    "failed_request_hash": HASH,
                    "failure_code": {"const": "peer_transport_ambiguous"},
                    "ciphertext_replayed_exactly": {"const": True},
                    "origin_event_ids": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 256,
                            "uniqueItems": True,
                            "items": UUID,
                        },
                    },
                    "isolated_heads_hashes": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "uniqueItems": True,
                        "items": HASH,
                    },
                    "opposite_ledgers_unaware": {"const": True},
                }
            ),
            "sync": closed(
                {
                    "transport_schema": {"const": "dm.peer-envelope/v1"},
                    "transport_profile": {
                        "const": "HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305"
                        "+ED25519+JCS/v1"
                    },
                    "plaintext_absent": {"const": True},
                    "fallback_absent": {"const": True},
                    "directions": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": direction,
                    },
                    "interruptions": {
                        "type": "array",
                        "minItems": 2,
                        "maxItems": 2,
                        "items": interruption,
                    },
                    "final_heads_hash": HASH,
                    "event_set_hash": HASH,
                    "event_count": UINT,
                    "write_free_exact_replay": {"const": True},
                    "duplicate_count": {"const": 0},
                }
            ),
            "adoption": closed(
                {
                    "target_event_id": UUID,
                    "legion_decision_id": UUID,
                    "daimonmatrix_decision_id": UUID,
                    "legion_reversal_id": UUID,
                    "legion_state": {"const": "reverted"},
                    "daimonmatrix_state": {"const": "rejected"},
                    "legion_remote_evidence": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "uniqueItems": True,
                        "items": UUID,
                    },
                    "daimonmatrix_remote_evidence": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "uniqueItems": True,
                        "items": UUID,
                    },
                    "immutable_decisions_preserved": {"const": True},
                }
            ),
            "succession": closed(
                {
                    "transition_id": {
                        "type": "string",
                        "pattern": "^dm:authority-epoch:v1:[A-Za-z0-9_-]{43}$",
                    },
                    "previous_incarnation_id": {
                        "type": "string",
                        "pattern": "^incarnation:[A-Za-z0-9._:-]{1,240}$",
                    },
                    "successor_incarnation_id": {
                        "type": "string",
                        "pattern": "^incarnation:[A-Za-z0-9._:-]{1,240}$",
                    },
                    "old_write_error": {"const": "origin_not_active"},
                    "new_event_id": UUID,
                    "new_lane_sequence": {"const": 1},
                    "old_high_water_preserved": {"const": True},
                    "sync_resumed": {"const": True},
                }
            ),
            "cluster": closed(
                {
                    "body_snapshot_hash": HASH,
                    "accepted_fence_hash": HASH,
                    "same_resource_second_holder": {"const": "fence_not_current"},
                    "stale_replay": {"const": "effect-truth-discrepancy"},
                    "different_resource": {"const": "verified"},
                    "ordinary_events_unaffected": {"const": True},
                }
            ),
            "historical": closed(
                {
                    "provenance_hash": HASH,
                    "validation": {"const": "verified"},
                    "identity_authority": {"const": False},
                    "event_authority": {"const": False},
                    "adoption_authority": {"const": False},
                    "fence_authority": {"const": False},
                }
            ),
            "isolation": closed({field: {"const": True} for field in isolation_fields}),
            "schedule": {
                "type": "array",
                "prefixItems": [{"const": item} for item in SCHEDULE],
                "minItems": len(SCHEDULE),
                "maxItems": len(SCHEDULE),
            },
            "receipt_hash": HASH,
            "receipt_id": {
                "type": "string",
                "pattern": "^dm:multihost-receipt:v1:[A-Za-z0-9_-]{43}$",
            },
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://daimon.local/schemas/multihost/v1/receipt.schema.json",
        "title": "Daimon Matrix multihost convergence receipt v1",
        **root,
    }


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, ensure_ascii=False).encode() + b"\n"


def load_fixture() -> dict[str, Any]:
    value = json.loads(FIXTURE.read_bytes())
    return validate_multihost_receipt(value)


def negative_vectors(valid: dict[str, Any]) -> dict[str, Any]:
    wrong_hash = copy.deepcopy(valid)
    wrong_hash["receipt_hash"] = "0" * 64
    alias = copy.deepcopy(valid)
    alias["authority"]["embodiments"][1]["signing_key_id"] = alias["authority"][
        "embodiments"
    ][0]["signing_key_id"]
    collapse = copy.deepcopy(valid)
    collapse["adoption"]["legion_state"] = "rejected"
    fence = copy.deepcopy(valid)
    fence["cluster"]["same_resource_second_holder"] = "verified"
    schedule = copy.deepcopy(valid)
    schedule["schedule"][3], schedule["schedule"][4] = (
        schedule["schedule"][4],
        schedule["schedule"][3],
    )
    leaked = copy.deepcopy(valid)
    leaked["authority"]["embodiments"][0]["body_ref"] = "/private/runtime"
    return {
        "negative/receipt-hash-tampered.json": wrong_hash,
        "negative/signing-key-aliased.json": alias,
        "negative/adoption-collapsed.json": collapse,
        "negative/fence-authority-fabricated.json": fence,
        "negative/schedule-reordered.json": schedule,
        "negative/private-path-leaked.json": leaked,
    }


def outputs() -> dict[Path, bytes]:
    valid = load_fixture()
    vectors = {"valid/receipt.json": valid, **negative_vectors(valid)}
    result = {
        ROOT / "schemas/multihost/v1/receipt.schema.json": json_bytes(receipt_schema())
    }
    for relative, value in vectors.items():
        result[VECTOR_ROOT / relative] = json_bytes(value)
    result[VECTOR_ROOT / "index.json"] = json_bytes(
        {
            "schema": "dm.multihost.vector-index/v1",
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


def refresh_fixture() -> None:
    provenance = json.loads(PROVENANCE.read_bytes())
    with tempfile.TemporaryDirectory(prefix="dm070-vector-") as temporary:
        receipt = run_synthetic_multihost(
            Path(temporary), source_commit="0" * 40, cluster_provenance=provenance
        )
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(json_bytes(receipt))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--refresh-fixture", action="store_true")
    args = parser.parse_args()
    if args.refresh_fixture:
        refresh_fixture()
    expected = outputs()
    if args.check:
        drift = [
            os.fspath(path.relative_to(ROOT))
            for path, raw in expected.items()
            if not path.exists() or path.read_bytes() != raw
        ]
        if drift:
            print(
                "DM-070 generated artifact drift: " + ", ".join(drift), file=sys.stderr
            )
            return 1
        return 0
    for path, raw in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
