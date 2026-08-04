#!/usr/bin/env python3
"""Generate deterministic root-bound DM-022 Weave vectors."""

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

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.identity import verify_genesis  # noqa: E402
from daimon_matrix.weave import (  # noqa: E402
    BeingManifest,
    EventSigner,
    RootAuthority,
    create_event,
)

DEFAULT_OUTPUT = ROOT / "vectors" / "weave" / "v1" / "root-bound"
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
    genesis = load(genesis_path)
    credential = load(credential_path)
    incarnation = load(incarnation_path)
    state = verify_genesis(genesis)
    credential_body = credential["body"]
    incarnation_body = incarnation["body"]
    row = {
        "body_ref": credential_body["body_ref"],
        "embodiment_credential_id": credential["artifact_id"],
        "embodiment_id": credential_body["embodiment_id"],
        "incarnation_authorization_id": incarnation["artifact_id"],
        "incarnation_id": incarnation_body["incarnation_id"],
        "status": "active",
    }
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": state.being_ref,
            "control_head": state.head,
            "history_binding_id": None,
            "revision": 1,
            "embodiments": [row],
        }
    )
    authority = RootAuthority(
        manifest,
        state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    signing_seed = seed("embodiment-signing")
    signer = EventSigner(credential_body["signing_key"]["key_id"], signing_seed)
    origin = {
        "embodiment_id": row["embodiment_id"],
        "incarnation_id": row["incarnation_id"],
        "principal_id": credential_body["transport_principals"][0]["principal_id"],
        "body_ref": row["body_ref"],
    }
    event = create_event(
        authority,
        origin,
        signer,
        event_id="00000000-0000-4000-8000-000000000201",
        sequence=1,
        previous_event_id=None,
        occurred_at_ms=NOW,
        causal_parents=[],
        kind="experience.observed",
        subject="dm022.root-bound",
        payload={"summary": "root-authorized independent ledger"},
        sensitivity="shareable",
    )
    negative = copy.deepcopy(event)
    negative["payload"]["summary"] = "changed after signing"
    index = {
        "schema": "dm.we.root-bound-vectors/v1",
        "manifest": "root-manifest.json",
        "valid_event": "root-experience.json",
        "negative_event": "negative/content-tampered.json",
        "identity": {
            "genesis": "../../../identity/v1/valid/genesis.json",
            "embodiment_credential": (
                "../../../identity/v1/valid/embodiment-credential.json"
            ),
            "incarnation_authorization": (
                "../../../identity/v1/valid/incarnation-authorization.json"
            ),
        },
    }
    write(output, "root-manifest.json", manifest.value)
    write(output, "root-experience.json", event)
    write(output, "negative/content-tampered.json", negative)
    write(output, "index.json", index)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    generate(arguments.out)


if __name__ == "__main__":
    main()
