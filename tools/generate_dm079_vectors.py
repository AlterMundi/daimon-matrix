#!/usr/bin/env python3
"""Generate deterministic signed DM-079 authority-epoch vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.authority_epochs import create_authority_epoch  # noqa: E402
from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.identity import (  # noqa: E402
    create_incarnation_authorization,
    verify_genesis,
)
from daimon_matrix.weave import BeingManifest  # noqa: E402

DEFAULT_OUTPUT = ROOT / "vectors" / "weave" / "v1" / "authority-epoch"
NOW = 1_800_000_000_000


def seed(label: str) -> bytes:
    return hashlib.sha256(f"dm-021-public-vector:{label}".encode()).digest()


def load(relative: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((ROOT / relative).read_bytes()))


def write(output: Path, relative: str, value: Any) -> None:
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def generate(output: Path) -> None:
    genesis_path = "vectors/identity/v1/valid/genesis.json"
    credential_path = "vectors/identity/v1/valid/embodiment-credential.json"
    incarnation_path = "vectors/identity/v1/valid/incarnation-authorization.json"
    previous_manifest_path = "vectors/weave/v1/root-bound/root-manifest.json"
    genesis = load(genesis_path)
    credential = load(credential_path)
    previous_authorization = load(incarnation_path)
    previous = BeingManifest.from_value(load(previous_manifest_path))
    state = verify_genesis(genesis)
    next_authorization = create_incarnation_authorization(
        credential,
        seed("embodiment-signing"),
        incarnation_id="incarnation:vector:legion:1",
        incarnation_sequence=1,
        started_at_ms=NOW + 1,
    )
    rows = copy.deepcopy(previous.value["embodiments"])
    rows[0]["status"] = "retired"
    rows.append(
        {
            **rows[0],
            "incarnation_authorization_id": next_authorization["artifact_id"],
            "incarnation_id": next_authorization["body"]["incarnation_id"],
            "status": "active",
        }
    )
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    successor = BeingManifest.from_value(
        {
            **previous.value,
            "revision": previous.value["revision"] + 1,
            "embodiments": rows,
        }
    )
    transition = create_authority_epoch(
        previous,
        successor,
        embodiment_id=credential["body"]["embodiment_id"],
        previous_incarnation_id=previous_authorization["body"]["incarnation_id"],
        successor_authorization=next_authorization,
        signing_seed=seed("embodiment-signing"),
        issued_at_ms=NOW + 1,
    )
    negative = copy.deepcopy(transition)
    negative["successor_revision"] += 1
    index = {
        "schema": "dm.we.authority-epoch-vectors/v1",
        "previous_manifest": "previous-manifest.json",
        "successor_manifest": "successor-manifest.json",
        "successor_authorization": "successor-incarnation-authorization.json",
        "valid_successor": "authority-epoch.json",
        "negative_successor": "negative/revision-tampered.json",
        "identity": {
            "genesis": "../../../identity/v1/valid/genesis.json",
            "embodiment_credential": (
                "../../../identity/v1/valid/embodiment-credential.json"
            ),
            "previous_incarnation_authorization": (
                "../../../identity/v1/valid/incarnation-authorization.json"
            ),
        },
        "control_head": state.head,
    }
    write(output, "previous-manifest.json", previous.value)
    write(output, "successor-manifest.json", successor.value)
    write(output, "successor-incarnation-authorization.json", next_authorization)
    write(output, "authority-epoch.json", transition)
    write(output, "negative/revision-tampered.json", negative)
    write(output, "index.json", index)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(arguments.out)


if __name__ == "__main__":
    main()
