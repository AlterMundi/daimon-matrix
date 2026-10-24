"""Pure receiving-reader examples shared by schema and runtime tests.

Do not import integration suites for inert schema input: strict type checking
must not acquire unrelated harnesses or runtime test dependencies.
"""

from __future__ import annotations

from typing import Any


def reader(**changes: Any) -> dict[str, Any]:
    return {
        "being_ref": "dm:being:v1:" + "A" * 43,
        "embodiment_id": "embodiment:synthetic",
        "credential_id": "credential:synthetic",
        "incarnation_id": "incarnation:synthetic",
        "authority_manifest_hash": "b" * 64,
        "receiving_selection_sha256": "c" * 64,
        "loaded_view_sha256": "d" * 64,
        "expires_at_ms": 20_000,
        "wire_read": ["dm.tribe.conversation/v1", "dm.tribe.direct-conversation/v1"],
        "authority_epochs": ["b" * 64],
        **changes,
    }


def reader_v2(**changes: Any) -> dict[str, Any]:
    value = reader()
    del value["expires_at_ms"]
    return {
        **value,
        "schema": "dm.receiving.reader/v2",
        "validity": {"mode": "until-revoked", "not_before_ms": 0},
        **changes,
    }
