"""Pure public-bundle authority composition; no runtime or custody loader."""

from collections.abc import Mapping
from typing import Any

from daimon_matrix.authority_epochs import RootHistoryAuthority
from daimon_matrix.operator_rebirth import (
    AUTHORITY_SCHEMA,
    authority_from_document,
    authority_from_runtime_bundle,
)
from daimon_matrix.weave import BeingManifest, RootAuthority


def public_history_authority(
    bundle: Mapping[str, Any],
) -> RootAuthority | RootHistoryAuthority:
    # Validate the complete public bundle/history with the canonical validator
    # before retaining its historical authorities for original event validation.
    active = authority_from_runtime_bundle(bundle)
    following = active
    reversed_history = []
    for epoch in reversed(bundle["authority_history"]):
        if set(epoch) == {"manifest", "successor"}:
            previous = RootAuthority(
                BeingManifest.from_value(epoch["manifest"]),
                following.state,
                following.credentials,
                following.incarnations,
            )
        else:
            previous = authority_from_document(
                {
                    "schema": AUTHORITY_SCHEMA,
                    **{
                        key: epoch[key]
                        for key in (
                            "control_artifacts",
                            "control_head",
                            "manifest",
                            "credentials",
                            "incarnations",
                        )
                    },
                }
            )
        reversed_history.append(previous)
        following = previous
    if not reversed_history:
        return active
    return RootHistoryAuthority(
        active,
        list(reversed(reversed_history)),
        [epoch["successor"] for epoch in bundle["authority_history"]],
    )
