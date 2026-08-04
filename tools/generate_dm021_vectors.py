#!/usr/bin/env python3
"""Generate deterministic public DM-021 identity conformance vectors."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix.canonical import canonical_bytes  # noqa: E402
from daimon_matrix.identity import (  # noqa: E402
    create_binding_activation,
    create_embodiment_credential,
    create_genesis,
    create_history_binding,
    create_incarnation_authorization,
    create_recovery,
    create_recovery_policy_change,
    create_revocation,
    create_root_rotation,
    ed25519_public,
    key_descriptor,
    verify_genesis,
    verify_successor,
    x25519_public,
)

OUTPUT = ROOT / "vectors" / "identity" / "v1"
NOW = 1_800_000_000_000


def seed(label: str) -> bytes:
    return hashlib.sha256(f"dm-021-public-vector:{label}".encode()).digest()


def write(relative: str, value: Any) -> None:
    path = OUTPUT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def without_role(artifact: dict[str, Any], role: str) -> dict[str, Any]:
    changed = copy.deepcopy(artifact)
    changed["signatures"] = [
        signature for signature in changed["signatures"] if signature["role"] != role
    ]
    return changed


def generate() -> None:
    root = [seed("root-a"), seed("root-b"), seed("root-c")]
    recovery = [seed("recovery-a"), seed("recovery-b"), seed("recovery-c")]
    genesis = create_genesis(
        root,
        2,
        recovery,
        2,
        created_at_ms=NOW,
        nonce=seed("nonce"),
    )
    state = verify_genesis(genesis)

    embodiment_seed = seed("embodiment-signing")
    transport_seed = seed("tribe-transport")
    credential = create_embodiment_credential(
        state,
        root,
        embodiment_seed,
        x25519_public(seed("embodiment-encryption")),
        embodiment_id="embodiment:vector:legion",
        body_ref="cluster:legion:compaii",
        purposes=["dm.we", "messages"],
        valid_from_ms=NOW - 1,
        valid_until_ms=NOW + 86_400_000,
        transport_principals=[
            {
                "key": key_descriptor("Ed25519", ed25519_public(transport_seed)),
                "principal_id": "compaii@legion",
                "scheme": "tribe-v1",
            }
        ],
    )
    incarnation = create_incarnation_authorization(
        credential,
        embodiment_seed,
        incarnation_id="incarnation:vector:legion:0",
        incarnation_sequence=0,
        started_at_ms=NOW,
    )

    replacement_root = [seed("new-root-a"), seed("new-root-b")]
    root_rotation = create_root_rotation(
        state,
        root,
        replacement_root,
        2,
        carry_forward_credentials=[credential["artifact_id"]],
    )
    replacement_recovery = [seed("new-recovery-a"), seed("new-recovery-b")]
    recovery_policy = create_recovery_policy_change(
        state,
        root,
        recovery,
        replacement_recovery,
        2,
    )
    revocation = create_revocation(
        state,
        root,
        embodiment_id="embodiment:vector:legion",
        cutoff_incarnation_sequence=0,
        revocation_generation=1,
    )

    branch_a_root = [seed("branch-a-1"), seed("branch-a-2")]
    branch_b_root = [seed("branch-b-1"), seed("branch-b-2")]
    branch_a = create_root_rotation(state, root, branch_a_root, 2)
    branch_b = create_root_rotation(state, root, branch_b_root, 2)
    branch_states = [
        verify_successor(branch_a, state),
        verify_successor(branch_b, state),
    ]
    recovered_root = [seed("recovered-root-a"), seed("recovered-root-b")]
    recovery_artifact = create_recovery(
        branch_states,
        recovery,
        recovered_root,
        2,
        revoke_embodiments=["embodiment:vector:compromised"],
    )

    weave_root = ROOT / "vectors" / "weave" / "v1"
    manifest = json.loads((weave_root / "manifest.json").read_bytes())
    event = json.loads((weave_root / "configuration-proposal.json").read_bytes())
    head = {
        "content_hash": event["content_hash"],
        "event_id": event["event_id"],
        "incarnation_id": event["origin"]["incarnation_id"],
        "origin_embodiment_id": event["origin"]["embodiment_id"],
        "sequence": event["sequence"],
        "signer_key_id": event["signature"]["kid"],
    }
    binding = create_history_binding(
        state,
        root,
        provisional_being_ref=manifest["being_ref"],
        manifest_bytes=canonical_bytes(manifest),
        manifest_revision=manifest["revision"],
        accepted_heads=[head],
    )
    activation = create_binding_activation(state, root, binding)

    valid = {
        "genesis": genesis,
        "embodiment-credential": credential,
        "incarnation-authorization": incarnation,
        "root-rotation": root_rotation,
        "recovery-policy": recovery_policy,
        "revocation": revocation,
        "recovery": recovery_artifact,
        "history-binding": binding,
        "binding-activation": activation,
    }
    support = {"fork-branch-a": branch_a, "fork-branch-b": branch_b}
    negative = {
        "genesis-missing-root-threshold": without_role(genesis, "root-authorization"),
        "credential-missing-acceptance": without_role(
            credential, "embodiment-acceptance"
        ),
        "incarnation-missing-authorization": without_role(
            incarnation, "incarnation-authorization"
        ),
        "rotation-missing-new-root-possession": without_role(
            root_rotation, "new-root-possession"
        ),
        "recovery-policy-missing-old-recovery": without_role(
            recovery_policy, "recovery-authorization"
        ),
        "revocation-missing-root-threshold": without_role(
            revocation, "root-authorization"
        ),
        "recovery-omits-recovery-threshold": without_role(
            recovery_artifact, "recovery-authorization"
        ),
        "binding-missing-root-threshold": without_role(binding, "root-authorization"),
        "activation-missing-root-threshold": without_role(
            activation, "root-authorization"
        ),
    }

    for name, artifact in valid.items():
        write(f"valid/{name}.json", artifact)
    for name, artifact in support.items():
        write(f"support/{name}.json", artifact)
    for name, artifact in negative.items():
        write(f"negative/{name}.json", artifact)

    index = {
        "accepted_head": head,
        "negative": {name: f"negative/{name}.json" for name in sorted(negative)},
        "schema": "dm.identity.vectors/v1",
        "support": {name: f"support/{name}.json" for name in sorted(support)},
        "valid": {name: f"valid/{name}.json" for name in sorted(valid)},
        "weave_event": "../../weave/v1/configuration-proposal.json",
        "weave_manifest": "../../weave/v1/manifest.json",
    }
    write("index.json", index)


if __name__ == "__main__":
    generate()
