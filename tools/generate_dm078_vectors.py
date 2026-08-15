#!/usr/bin/env python3
"""Generate deterministic DM-078 additional-embodiment ceremony vectors."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.identity import verify_genesis  # noqa: E402
from daimon_matrix.operator_rebirth import (  # noqa: E402
    authorize_enrollment_request,
    create_enrollment_request,
)
from daimon_matrix.weave import BeingManifest, RootAuthority  # noqa: E402

DEFAULT_OUTPUT = ROOT / "vectors" / "weave" / "v1" / "embodiment-enrollment"
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
    manifest_path = "vectors/weave/v1/root-bound/root-manifest.json"
    genesis = load(genesis_path)
    credential = load(credential_path)
    incarnation = load(incarnation_path)
    previous = BeingManifest.from_value(load(manifest_path))
    state = verify_genesis(genesis)
    base = RootAuthority(
        previous,
        state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    request = create_enrollment_request(
        base,
        signing_seed=seed("dm078-fresh-signing"),
        encryption_private=seed("dm078-fresh-encryption"),
        transport_seed=seed("dm078-fresh-transport"),
        body_ref="cluster:vector:fresh",
        embodiment_id="embodiment:vector:fresh",
        incarnation_id="incarnation:vector:fresh:0",
        principal_id="compaii@vector-fresh",
        created_at_ms=NOW + 10,
        expires_at_ms=NOW + 60_010,
        nonce=seed("dm078-request-nonce"),
    )
    activation = authorize_enrollment_request(
        request,
        base,
        root_seeds=[seed("root-a"), seed("root-b")],
        issued_at_ms=NOW + 20,
    )
    bad_request = copy.deepcopy(request)
    bad_request["signature"]["value"] = "A" * 86
    bad_transition = copy.deepcopy(activation["body"]["transition"])
    bad_transition["content_hash"] = "0" * 64
    index = {
        "schema": "dm.we.embodiment-enrollment-vectors/v1",
        "previous_manifest": "previous-manifest.json",
        "request": "enrollment-request.json",
        "activation": "activation.json",
        "successor_manifest": "successor-manifest.json",
        "credential": "embodiment-credential.json",
        "incarnation": "incarnation-authorization.json",
        "transition": "embodiment-enrollment.json",
        "negative_request": "negative/request-signature-tampered.json",
        "negative_transition": "negative/transition-hash-tampered.json",
        "identity": {
            "genesis": "../../../identity/v1/valid/genesis.json",
            "existing_embodiment_credential": (
                "../../../identity/v1/valid/embodiment-credential.json"
            ),
            "existing_incarnation_authorization": (
                "../../../identity/v1/valid/incarnation-authorization.json"
            ),
        },
        "control_head": state.head,
    }
    write(output, "previous-manifest.json", previous.value)
    write(output, "enrollment-request.json", request)
    write(output, "activation.json", activation)
    write(output, "successor-manifest.json", activation["body"]["successor_manifest"])
    write(output, "embodiment-credential.json", activation["body"]["credential"])
    write(output, "incarnation-authorization.json", activation["body"]["incarnation"])
    write(output, "embodiment-enrollment.json", activation["body"]["transition"])
    write(output, "negative/request-signature-tampered.json", bad_request)
    write(output, "negative/transition-hash-tampered.json", bad_transition)
    write(output, "index.json", index)


def check() -> bool:
    with tempfile.TemporaryDirectory(prefix="dm078-vectors-") as directory:
        generated = Path(directory)
        generate(generated)
        expected_files = sorted(
            path.relative_to(DEFAULT_OUTPUT)
            for path in DEFAULT_OUTPUT.rglob("*")
            if path.is_file()
        )
        generated_files = sorted(
            path.relative_to(generated)
            for path in generated.rglob("*")
            if path.is_file()
        )
        return expected_files == generated_files and all(
            (DEFAULT_OUTPUT / relative).read_bytes()
            == (generated / relative).read_bytes()
            for relative in expected_files
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.check:
        if arguments.out != DEFAULT_OUTPUT:
            parser.error("--check cannot be combined with --out")
        if not check():
            raise SystemExit("DM-078 vectors differ; regenerate them")
        return
    if arguments.out == DEFAULT_OUTPUT and DEFAULT_OUTPUT.exists():
        shutil.rmtree(DEFAULT_OUTPUT)
    generate(arguments.out)


if __name__ == "__main__":
    main()
