#!/usr/bin/env python3
"""Generate deterministic DM-078 recovery-rebirth ceremony vectors."""

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
from daimon_matrix.identity import create_recovery, verify_genesis  # noqa: E402
from daimon_matrix.operator_rebirth import (  # noqa: E402
    authorize_recovery_enrollment_request,
    create_enrollment_request,
    recovery_request_base,
)
from daimon_matrix.weave import BeingManifest, RootAuthority  # noqa: E402

DEFAULT_OUTPUT = ROOT / "vectors" / "weave" / "v1" / "recovery-rebirth"
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
    replacement_roots = [
        seed("dm078-recovered-root-a"),
        seed("dm078-recovered-root-b"),
    ]
    recovery = create_recovery(
        [state],
        [seed("recovery-a"), seed("recovery-b")],
        replacement_roots,
        2,
        revoke_embodiments=["embodiment:vector:legion"],
    )
    request = create_enrollment_request(
        recovery_request_base(base, recovery),
        signing_seed=seed("dm078-recovery-signing"),
        encryption_private=seed("dm078-recovery-encryption"),
        transport_seed=seed("dm078-recovery-transport"),
        body_ref="cluster:vector:recovered",
        embodiment_id="embodiment:vector:recovered",
        incarnation_id="incarnation:vector:recovered:0",
        principal_id="compaii@vector-recovered",
        created_at_ms=NOW + 10,
        expires_at_ms=NOW + 60_010,
        nonce=seed("dm078-recovery-request-nonce"),
    )
    activation = authorize_recovery_enrollment_request(
        request,
        base,
        recovery,
        replacement_root_seeds=replacement_roots,
        issued_at_ms=NOW + 20,
    )
    bad_recovery = copy.deepcopy(recovery)
    bad_recovery["signatures"][0]["value"] = "A" * 86
    bad_transition = copy.deepcopy(activation["body"]["transition"])
    bad_transition["content_hash"] = "0" * 64
    index = {
        "schema": "dm.we.recovery-rebirth-vectors/v1",
        "previous_manifest": "previous-manifest.json",
        "recovery_artifact": "recovery-artifact.json",
        "request": "enrollment-request.json",
        "activation": "activation.json",
        "successor_manifest": "successor-manifest.json",
        "credential": "embodiment-credential.json",
        "incarnation": "incarnation-authorization.json",
        "transition": "recovery-rebirth.json",
        "negative_recovery": "negative/recovery-signature-tampered.json",
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
        "previous_control_head": state.head,
        "recovered_control_head": recovery["artifact_id"],
    }
    write(output, "previous-manifest.json", previous.value)
    write(output, "recovery-artifact.json", recovery)
    write(output, "enrollment-request.json", request)
    write(output, "activation.json", activation)
    write(output, "successor-manifest.json", activation["body"]["successor_manifest"])
    write(output, "embodiment-credential.json", activation["body"]["credential"])
    write(output, "incarnation-authorization.json", activation["body"]["incarnation"])
    write(output, "recovery-rebirth.json", activation["body"]["transition"])
    write(output, "negative/recovery-signature-tampered.json", bad_recovery)
    write(output, "negative/transition-hash-tampered.json", bad_transition)
    write(output, "index.json", index)


def check() -> bool:
    with tempfile.TemporaryDirectory(prefix="dm078-recovery-vectors-") as directory:
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
            raise SystemExit("DM-078 recovery vectors differ; regenerate them")
        return
    if arguments.out == DEFAULT_OUTPUT and DEFAULT_OUTPUT.exists():
        shutil.rmtree(DEFAULT_OUTPUT)
    generate(arguments.out)


if __name__ == "__main__":
    main()
