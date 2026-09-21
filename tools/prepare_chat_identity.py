#!/usr/bin/env python3
"""Prepare one owner-local chat identity; no services, network or Hermes edits.

This explicit single-owner setup creates distinct root/recovery keys with 1-of-1
thresholds. Unlock material remains in owner-only local files alongside encrypted
custody. This is NOT an off-device backup or distributed custody. Only the signed
public identity document is intended for sharing with the onboarding operator.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from pathlib import Path

from daimon_matrix import authority_epochs, identity
from daimon_matrix import operator_first_embodiment as first
from daimon_matrix import operator_genesis as genesis
from daimon_matrix import operator_rebirth as rebirth
from daimon_matrix.canonical import canonical_bytes, unb64url
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.messaging_config import create_binding
from daimon_matrix.native_egress import closed_visibility
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import BeingManifest, RootAuthority


def now() -> int:
    return time.time_ns() // 1_000_000


def write(path: Path, value: object) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare(output: Path, *, label: str, body_ref: str, principal_id: str) -> Path:
    output = output.absolute()
    # Validate owner and ancestor permissions before generating any keys.
    from daimon_matrix.messaging_config import _directory

    _directory(output.parent)
    output.mkdir(mode=0o700)  # Never overwrite or silently reinitialize custody.
    holder_password, body_password = secrets.token_bytes(32), secrets.token_bytes(32)
    write(output / "holder.password", holder_password)
    write(output / "body.password", body_password)
    descriptors = [
        genesis.create_holder_package(
            output / role, role, lambda: bytearray(holder_password)
        )
        for role in ("root", "recovery")
    ]
    intent = genesis.create_intent(
        descriptors,
        root_threshold=1,
        recovery_threshold=1,
        created_at_ms=now(),
        nonce=secrets.token_bytes(32),
    )
    document = genesis.aggregate_intent(
        intent,
        [
            genesis.create_holder_share(
                intent, output / role, lambda: bytearray(holder_password)
            )
            for role in ("root", "recovery")
        ],
    )
    write(output / "genesis.json", document)
    preparation = first.prepare_target(
        output / "preparation",
        document,
        {
            "schema": rebirth.TARGET_PROFILE_SCHEMA,
            "label": label,
            "body_ref": body_ref,
            "principal_id": principal_id,
            "listen_host": "127.0.0.1",
            "listen_port": 8687,
            "advertised_endpoint": "http://127.0.0.1:8687/dm-peer/v1",
            "targets": [],
        },
        lambda: bytearray(body_password),
        created_at_ms=now(),
    )
    request = json.loads((output / "preparation" / "request.json").read_bytes())
    share = first.create_root_share(
        document,
        request,
        output / "root",
        lambda: bytearray(holder_password),
        observed_at_ms=now(),
    )
    activation = first.aggregate_activation(
        document, request, [share], observed_at_ms=now()
    )
    first.activate_runtime(
        output / "package",
        document,
        output / "preparation",
        preparation,
        request,
        activation,
        lambda: bytearray(body_password),
    )
    runtime_root = output / "package" / "runtime"
    bundle_path = runtime_root / "runtime.json"
    bundle = json.loads(bundle_path.read_bytes())
    old = rebirth.authority_from_runtime_bundle(bundle)
    origin = bundle["local_origin"]
    member = old.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    body = old.credentials[member["embodiment_credential_id"]]["body"]
    custody = EncryptedKeystore(runtime_root / "custody.json").open(
        lambda: bytearray(body_password)
    )
    signing = custody.secrets[bundle["keystore"]["signing_slot"]]
    holder = EncryptedKeystore(output / "root" / "holder.json").open(
        lambda: bytearray(holder_password)
    )
    roots = [holder.secrets["genesis.root.v1:holder"]]
    credential = identity.create_embodiment_credential_v2(
        old.state,
        roots,
        signing,
        unb64url(body["encryption_key"]["public"], length=32),
        embodiment_id=body["embodiment_id"],
        body_ref=body["body_ref"],
        purposes=body["purposes"],
        revocation_generation=body["revocation_generation"],
        transport_principals=body["transport_principals"],
        validity={"mode": "until-revoked", "not_before_ms": body["valid_from_ms"]},
    )
    prior = old.incarnations[member["incarnation_authorization_id"]]["body"]
    incarnation = identity.create_incarnation_authorization(
        credential,
        signing,
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=prior["incarnation_sequence"],
        started_at_ms=prior["started_at_ms"],
    )
    manifest = copy.deepcopy(old.manifest.value)
    manifest["revision"] += 1
    manifest["embodiments"][0].update(
        embodiment_credential_id=credential["artifact_id"],
        incarnation_authorization_id=incarnation["artifact_id"],
    )
    active = RootAuthority(
        BeingManifest.from_value(manifest),
        old.state,
        {**old.credentials, credential["artifact_id"]: credential},
        {**old.incarnations, incarnation["artifact_id"]: incarnation},
    )
    transition = authority_epochs.create_credential_succession(
        old,
        active,
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        migration_id=str(uuid.uuid4()),
        issued_at_ms=now(),
        root_seeds=roots,
        signing_seed=signing,
    )
    # This target has never been loaded or served: there is no native history to
    # migrate. Preserve the complete signed first-credential succession anyway.
    bundle.update(
        schema="dm.runtime.bundle/v8",
        manifest=manifest,
        credentials=list(active.credentials.values()),
        incarnations=list(active.incarnations.values()),
        authority_history=[{"manifest": old.manifest.value, "successor": transition}],
    )
    staged = runtime_root / "runtime-chat-prepared.json"
    write(staged, bundle)
    os.replace(staged, bundle_path)
    rebirth._fsync_directory(runtime_root)
    runtime = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(body_password),
        clock=now,
        egress=closed_visibility(clock=now, catalog_mode="migrate"),
    )
    public = {
        "schema": "dm.onboarding.prepared-chat-identity/v1",
        "authority": {
            "schema": rebirth.AUTHORITY_SCHEMA,
            **{
                key: bundle[key]
                for key in (
                    "control_artifacts",
                    "control_head",
                    "manifest",
                    "credentials",
                    "incarnations",
                )
            },
        },
        "authority_history": bundle["authority_history"],
        "origin": origin,
        "runtime_id": runtime.service.runtime_id,
        "runtime_label": runtime.service.runtime_label,
    }
    public_path = output / "public-identity.json"
    write(public_path, {"document": public, "binding": create_binding(runtime, public)})
    rebirth._fsync_directory(output)
    return public_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--body-ref", required=True)
    parser.add_argument("--principal-id", required=True)
    args = parser.parse_args()
    public = prepare(
        args.output,
        label=args.label,
        body_ref=args.body_ref,
        principal_id=args.principal_id,
    )
    print(
        json.dumps(
            {
                "public_identity_file": str(public),
                "public_identity_sha256": hashlib.sha256(
                    public.read_bytes()
                ).hexdigest(),
                "services_started": 0,
                "network_used": False,
                "hermes_modified": False,
                "custody": "single-owner-local; not an off-device backup",
                "share_only": "public-identity.json; never passwords or custody files",
            }
        )
    )


if __name__ == "__main__":
    main()
