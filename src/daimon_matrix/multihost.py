"""Closed public evidence for the DM-070 multihost convergence journey.

This module validates evidence; it is not a synchronization, membership, or
resource-fence authority.  The executable journey composes the existing
Matrix ledger/transport contracts and injects Cluster truth at the DM-037
boundary, then reduces private runtime state to this bounded receipt.
"""

from __future__ import annotations

import copy
import hashlib
import re
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final

from .canonical import CanonicalError, b64url, canonical_bytes

RECEIPT_SCHEMA: Final = "dm.multihost-convergence-receipt/v1"
PROVENANCE_SCHEMA: Final = "dm.cluster-provenance/v1"
RUN_PROFILE: Final = "installed-isolated-loopback/v1"
RECEIPT_DOMAIN: Final = b"daimon/multihost-convergence-receipt/v1\x00"
PROVENANCE_DOMAIN: Final = b"daimon/cluster-provenance/v1\x00"
MAX_DOCUMENT_BYTES: Final = 512 * 1024
MAX_UINT: Final = 2**53 - 1

_HASH = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DERIVED = re.compile(r"^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$")
_ORIGIN = re.compile(r"^(?:embodiment|incarnation):[A-Za-z0-9._:-]{1,240}$")
_FORBIDDEN_KEY = re.compile(
    r"(?:^|_)(?:endpoint|host_path|password|private_key|secret|socket_path|token)"
    r"(?:$|_)",
    re.IGNORECASE,
)
_FORBIDDEN_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|^(?:/|~[/\\]|file:))",
    re.IGNORECASE,
)

SCHEDULE: Final = (
    "awake",
    "partition",
    "independent-append",
    "heal-forward-page-1",
    "restart-after-receiver-commit",
    "replay-forward-page-1",
    "restart-before-receiver-commit",
    "resume-forward",
    "heal-reverse",
    "write-free-replay",
    "independent-decisions",
    "decision-convergence",
    "local-reversal",
    "reversal-convergence",
    "authority-epoch-advance",
    "successor-sync",
    "cluster-fence-check",
    "historical-receipt-check",
)


class MultihostEvidenceError(ValueError):
    """Stable fail-closed error for public DM-070 evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MultihostEvidenceError(code)
    return value


def _canonical(value: Any, code: str) -> bytes:
    try:
        encoded = canonical_bytes(value)
    except CanonicalError as exception:
        raise MultihostEvidenceError(code) from exception
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise MultihostEvidenceError("multihost_evidence_too_large")
    return encoded


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise MultihostEvidenceError(code)
    _canonical(value, code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise MultihostEvidenceError(code)
    return value


def _commit(value: Any, code: str) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise MultihostEvidenceError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise MultihostEvidenceError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise MultihostEvidenceError(code) from exception
    if str(parsed) != value:
        raise MultihostEvidenceError(code)
    return value


def _uint(value: Any, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_UINT
    ):
        raise MultihostEvidenceError(code)
    return value


def _true(value: Any, code: str) -> None:
    if value is not True:
        raise MultihostEvidenceError(code)


def _safe_public_tree(value: Any, *, depth: int = 0) -> None:
    if depth > 14:
        raise MultihostEvidenceError("multihost_evidence_too_deep")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 4096 or _FORBIDDEN_VALUE.search(value):
            raise MultihostEvidenceError("private_evidence_forbidden")
        return
    if isinstance(value, list):
        for item in value:
            _safe_public_tree(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or (
                _FORBIDDEN_KEY.search(key) and key not in {"public_receipt_secret_free"}
            ):
                raise MultihostEvidenceError("private_evidence_forbidden")
            _safe_public_tree(item, depth=depth + 1)
        return
    raise MultihostEvidenceError("invalid_multihost_evidence")


def _digest(domain: bytes, value: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(
        domain + _canonical(value, "invalid_multihost_evidence")
    ).digest()


def validate_cluster_provenance(value: Any) -> dict[str, Any]:
    """Validate a content-addressed, read-only pin to redacted Cluster evidence."""

    row = _closed(
        value,
        {
            "schema",
            "repository",
            "commit",
            "hosting_contract",
            "historical_canary",
            "authority_limits",
            "provenance_hash",
        },
        "invalid_cluster_provenance",
    )
    if row["schema"] != PROVENANCE_SCHEMA:
        raise MultihostEvidenceError("invalid_cluster_provenance")
    if row["repository"] != "https://github.com/nicoechaniz/daimon-cluster":
        raise MultihostEvidenceError("invalid_cluster_provenance")
    _commit(row["commit"], "invalid_cluster_provenance")
    hosting = _closed(
        row["hosting_contract"],
        {
            "issue",
            "issue_state",
            "contract_path",
            "contract_sha256",
            "process_test_path",
            "process_test_sha256",
        },
        "invalid_cluster_provenance",
    )
    canary = _closed(
        row["historical_canary"],
        {
            "issue",
            "issue_state",
            "receipt_path",
            "receipt_sha256",
            "result",
            "matrix_commit",
            "cluster_commit",
            "tribe_bridge_commit",
        },
        "invalid_cluster_provenance",
    )
    if (
        hosting["issue"] != 48
        or hosting["issue_state"] != "closed"
        or canary["issue"] != 43
        or canary["issue_state"] != "closed"
        or canary["result"] != "PASS"
    ):
        raise MultihostEvidenceError("invalid_cluster_provenance")
    for item, expected in (
        (hosting["contract_path"], "clusterctl/matrix_host.py"),
        (hosting["process_test_path"], "tests/test_matrix_host_process.py"),
        (
            canary["receipt_path"],
            "docs/verification/weave-r6-legion-daimonmatrix.md",
        ),
    ):
        if item != expected:
            raise MultihostEvidenceError("invalid_cluster_provenance")
    for digest in (
        hosting["contract_sha256"],
        hosting["process_test_sha256"],
        canary["receipt_sha256"],
    ):
        _hash(digest, "invalid_cluster_provenance")
    for commit in (
        canary["matrix_commit"],
        canary["cluster_commit"],
        canary["tribe_bridge_commit"],
    ):
        _commit(commit, "invalid_cluster_provenance")
    limits = _closed(
        row["authority_limits"],
        {
            "redacted",
            "read_only",
            "identity_authority",
            "event_authority",
            "adoption_authority",
            "fence_authority",
        },
        "invalid_cluster_provenance",
    )
    _true(limits["redacted"], "invalid_cluster_provenance")
    _true(limits["read_only"], "invalid_cluster_provenance")
    if any(
        limits[field] is not False
        for field in (
            "identity_authority",
            "event_authority",
            "adoption_authority",
            "fence_authority",
        )
    ):
        raise MultihostEvidenceError("cluster_provenance_claims_authority")
    core = {
        key: copy.deepcopy(item)
        for key, item in row.items()
        if key != "provenance_hash"
    }
    expected_hash = hashlib.sha256(
        PROVENANCE_DOMAIN + _canonical(core, "invalid_cluster_provenance")
    ).hexdigest()
    if _hash(row["provenance_hash"], "invalid_cluster_provenance") != expected_hash:
        raise MultihostEvidenceError("cluster_provenance_hash_mismatch")
    _safe_public_tree(row)
    return copy.deepcopy(dict(row))


def _origin_row(value: Any) -> dict[str, Any]:
    row = _closed(
        value,
        {
            "label",
            "body_ref",
            "embodiment_id",
            "initial_incarnation_id",
            "current_incarnation_id",
            "credential_id",
            "signing_key_id",
            "encryption_key_id",
            "transport_key_id",
            "capability_id",
            "state_fingerprint",
        },
        "invalid_multihost_origin",
    )
    if row["label"] not in {"legion", "daimonmatrix"}:
        raise MultihostEvidenceError("invalid_multihost_origin")
    _text(row["body_ref"], "invalid_multihost_origin")
    for field in ("embodiment_id", "initial_incarnation_id", "current_incarnation_id"):
        if not isinstance(row[field], str) or _ORIGIN.fullmatch(row[field]) is None:
            raise MultihostEvidenceError("invalid_multihost_origin")
    for field in (
        "credential_id",
        "signing_key_id",
        "encryption_key_id",
        "transport_key_id",
        "capability_id",
    ):
        if not isinstance(row[field], str) or _DERIVED.fullmatch(row[field]) is None:
            raise MultihostEvidenceError("invalid_multihost_origin")
    _hash(row["state_fingerprint"], "invalid_multihost_origin")
    return copy.deepcopy(dict(row))


def _hash_list(
    value: Any, code: str, *, minimum: int = 1, maximum: int = 256
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise MultihostEvidenceError(code)
    result = [_hash(item, code) for item in value]
    if len(set(result)) != len(result):
        raise MultihostEvidenceError(code)
    return result


def _uuid_list(
    value: Any, code: str, *, minimum: int = 1, maximum: int = 256
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise MultihostEvidenceError(code)
    result = [_uuid(item, code) for item in value]
    if len(set(result)) != len(result):
        raise MultihostEvidenceError(code)
    return result


def _validate_receipt_core(value: Any) -> dict[str, Any]:
    core = _closed(
        value,
        {
            "schema",
            "run_profile",
            "source_commit",
            "package",
            "authority",
            "processes",
            "partition",
            "sync",
            "adoption",
            "succession",
            "cluster",
            "historical",
            "isolation",
            "schedule",
        },
        "invalid_multihost_receipt",
    )
    if core["schema"] != RECEIPT_SCHEMA or core["run_profile"] != RUN_PROFILE:
        raise MultihostEvidenceError("invalid_multihost_receipt")
    _commit(core["source_commit"], "invalid_multihost_receipt")
    package = _closed(
        core["package"], {"name", "version", "entrypoint"}, "invalid_multihost_receipt"
    )
    if package != {
        "name": "daimon-matrix",
        "version": "0.1.0rc1",
        "entrypoint": "daimon-synthetic-multihost",
    }:
        raise MultihostEvidenceError("invalid_multihost_receipt")

    authority = _closed(
        core["authority"],
        {
            "being_ref",
            "control_head",
            "initial_manifest_hash",
            "successor_manifest_hash",
            "embodiments",
        },
        "invalid_multihost_authority",
    )
    if not isinstance(authority["being_ref"], str) or not authority[
        "being_ref"
    ].startswith("dm:being:v1:"):
        raise MultihostEvidenceError("invalid_multihost_authority")
    if not isinstance(authority["control_head"], str) or not authority[
        "control_head"
    ].startswith("dm:identity:v1:"):
        raise MultihostEvidenceError("invalid_multihost_authority")
    initial_manifest = _hash(
        authority["initial_manifest_hash"], "invalid_multihost_authority"
    )
    successor_manifest = _hash(
        authority["successor_manifest_hash"], "invalid_multihost_authority"
    )
    if initial_manifest == successor_manifest:
        raise MultihostEvidenceError("authority_epoch_not_advanced")
    if (
        not isinstance(authority["embodiments"], list)
        or len(authority["embodiments"]) != 2
    ):
        raise MultihostEvidenceError("invalid_multihost_authority")
    origins = [_origin_row(item) for item in authority["embodiments"]]
    if [item["label"] for item in origins] != ["legion", "daimonmatrix"]:
        raise MultihostEvidenceError("invalid_multihost_authority")
    distinct_fields = (
        "body_ref",
        "embodiment_id",
        "initial_incarnation_id",
        "credential_id",
        "signing_key_id",
        "encryption_key_id",
        "transport_key_id",
        "capability_id",
        "state_fingerprint",
    )
    if any(len({item[field] for item in origins}) != 2 for field in distinct_fields):
        raise MultihostEvidenceError("multihost_isolation_alias")
    if (
        origins[0]["current_incarnation_id"] == origins[0]["initial_incarnation_id"]
        or origins[1]["current_incarnation_id"] != origins[1]["initial_incarnation_id"]
    ):
        raise MultihostEvidenceError("invalid_incarnation_succession")

    processes = _closed(
        core["processes"],
        {
            "daemon_count",
            "simultaneously_awake",
            "me_response_hashes",
            "we_response_hashes",
            "restart_count",
            "fixed_test_clock_ms",
        },
        "invalid_multihost_process_evidence",
    )
    if (
        processes["daemon_count"] != 2
        or _uint(processes["restart_count"], "invalid_multihost_process_evidence") < 3
    ):
        raise MultihostEvidenceError("invalid_multihost_process_evidence")
    _true(processes["simultaneously_awake"], "invalid_multihost_process_evidence")
    if (
        len(
            _hash_list(
                processes["me_response_hashes"], "invalid_multihost_process_evidence"
            )
        )
        != 2
        or len(
            _hash_list(
                processes["we_response_hashes"], "invalid_multihost_process_evidence"
            )
        )
        != 2
    ):
        raise MultihostEvidenceError("invalid_multihost_process_evidence")
    _uint(processes["fixed_test_clock_ms"], "invalid_multihost_process_evidence")

    partition = _closed(
        core["partition"],
        {
            "failed_request_id",
            "failed_request_hash",
            "failure_code",
            "ciphertext_replayed_exactly",
            "origin_event_ids",
            "isolated_heads_hashes",
            "opposite_ledgers_unaware",
        },
        "invalid_partition_evidence",
    )
    _uuid(partition["failed_request_id"], "invalid_partition_evidence")
    _hash(partition["failed_request_hash"], "invalid_partition_evidence")
    if partition["failure_code"] != "peer_transport_ambiguous":
        raise MultihostEvidenceError("invalid_partition_evidence")
    _true(partition["ciphertext_replayed_exactly"], "invalid_partition_evidence")
    if (
        not isinstance(partition["origin_event_ids"], list)
        or len(partition["origin_event_ids"]) != 2
    ):
        raise MultihostEvidenceError("invalid_partition_evidence")
    partition_events = [
        _uuid_list(item, "invalid_partition_evidence")
        for item in partition["origin_event_ids"]
    ]
    if set(partition_events[0]) & set(partition_events[1]):
        raise MultihostEvidenceError("invalid_partition_evidence")
    if (
        len(
            _hash_list(partition["isolated_heads_hashes"], "invalid_partition_evidence")
        )
        != 2
    ):
        raise MultihostEvidenceError("invalid_partition_evidence")
    _true(partition["opposite_ledgers_unaware"], "invalid_partition_evidence")

    sync = _closed(
        core["sync"],
        {
            "transport_schema",
            "transport_profile",
            "plaintext_absent",
            "fallback_absent",
            "directions",
            "interruptions",
            "final_heads_hash",
            "event_set_hash",
            "event_count",
            "write_free_exact_replay",
            "duplicate_count",
        },
        "invalid_sync_evidence",
    )
    if (
        sync["transport_schema"] != "dm.peer-envelope/v1"
        or sync["transport_profile"]
        != "HPKE-X25519-HKDF-SHA256-CHACHA20POLY1305+ED25519+JCS/v1"
    ):
        raise MultihostEvidenceError("invalid_sync_evidence")
    _true(sync["plaintext_absent"], "invalid_sync_evidence")
    _true(sync["fallback_absent"], "invalid_sync_evidence")
    if not isinstance(sync["directions"], list) or len(sync["directions"]) != 2:
        raise MultihostEvidenceError("invalid_sync_evidence")
    expected_pairs = (
        (origins[0]["embodiment_id"], origins[1]["embodiment_id"]),
        (origins[1]["embodiment_id"], origins[0]["embodiment_id"]),
    )
    for direction, expected in zip(sync["directions"], expected_pairs, strict=True):
        item = _closed(
            direction,
            {
                "receiver_embodiment_id",
                "sender_embodiment_id",
                "request_hashes",
                "page_hashes",
                "receipt_hashes",
                "pages",
            },
            "invalid_sync_evidence",
        )
        if (item["receiver_embodiment_id"], item["sender_embodiment_id"]) != expected:
            raise MultihostEvidenceError("invalid_sync_evidence")
        request_hashes = _hash_list(item["request_hashes"], "invalid_sync_evidence")
        page_hashes = _hash_list(item["page_hashes"], "invalid_sync_evidence")
        receipt_hashes = _hash_list(item["receipt_hashes"], "invalid_sync_evidence")
        if not (
            len(request_hashes)
            == len(page_hashes)
            == len(receipt_hashes)
            == _uint(item["pages"], "invalid_sync_evidence")
        ):
            raise MultihostEvidenceError("invalid_sync_evidence")
    if not isinstance(sync["interruptions"], list) or len(sync["interruptions"]) != 2:
        raise MultihostEvidenceError("invalid_sync_evidence")
    for item, boundary in zip(
        sync["interruptions"],
        ("after-receiver-commit", "before-receiver-commit"),
        strict=True,
    ):
        interruption = _closed(
            item,
            {
                "boundary",
                "request_hash",
                "page_hash",
                "receipt_hash",
                "process_restarted",
                "exact_replay",
            },
            "invalid_sync_evidence",
        )
        if interruption["boundary"] != boundary:
            raise MultihostEvidenceError("invalid_sync_evidence")
        for field in ("request_hash", "page_hash", "receipt_hash"):
            _hash(interruption[field], "invalid_sync_evidence")
        _true(interruption["process_restarted"], "invalid_sync_evidence")
        _true(interruption["exact_replay"], "invalid_sync_evidence")
    _hash(sync["final_heads_hash"], "invalid_sync_evidence")
    _hash(sync["event_set_hash"], "invalid_sync_evidence")
    if (
        _uint(sync["event_count"], "invalid_sync_evidence") < 8
        or sync["duplicate_count"] != 0
    ):
        raise MultihostEvidenceError("invalid_sync_evidence")
    _true(sync["write_free_exact_replay"], "invalid_sync_evidence")

    adoption = _closed(
        core["adoption"],
        {
            "target_event_id",
            "legion_decision_id",
            "daimonmatrix_decision_id",
            "legion_reversal_id",
            "legion_state",
            "daimonmatrix_state",
            "legion_remote_evidence",
            "daimonmatrix_remote_evidence",
            "immutable_decisions_preserved",
        },
        "invalid_adoption_evidence",
    )
    decision_ids = [
        _uuid(adoption[field], "invalid_adoption_evidence")
        for field in (
            "target_event_id",
            "legion_decision_id",
            "daimonmatrix_decision_id",
            "legion_reversal_id",
        )
    ]
    if (
        len(set(decision_ids)) != 4
        or adoption["target_event_id"] not in partition_events[0]
    ):
        raise MultihostEvidenceError("invalid_adoption_evidence")
    if (
        adoption["legion_state"] != "reverted"
        or adoption["daimonmatrix_state"] != "rejected"
    ):
        raise MultihostEvidenceError("adoption_winner_collapsed")
    if _uuid_list(adoption["legion_remote_evidence"], "invalid_adoption_evidence") != [
        adoption["daimonmatrix_decision_id"]
    ]:
        raise MultihostEvidenceError("invalid_adoption_evidence")
    if _uuid_list(
        adoption["daimonmatrix_remote_evidence"], "invalid_adoption_evidence"
    ) != [adoption["legion_decision_id"], adoption["legion_reversal_id"]]:
        raise MultihostEvidenceError("invalid_adoption_evidence")
    _true(adoption["immutable_decisions_preserved"], "invalid_adoption_evidence")

    succession = _closed(
        core["succession"],
        {
            "transition_id",
            "previous_incarnation_id",
            "successor_incarnation_id",
            "old_write_error",
            "new_event_id",
            "new_lane_sequence",
            "old_high_water_preserved",
            "sync_resumed",
        },
        "invalid_succession_evidence",
    )
    if not isinstance(succession["transition_id"], str) or not succession[
        "transition_id"
    ].startswith("dm:authority-epoch:v1:"):
        raise MultihostEvidenceError("invalid_succession_evidence")
    if (
        succession["previous_incarnation_id"] != origins[0]["initial_incarnation_id"]
        or succession["successor_incarnation_id"]
        != origins[0]["current_incarnation_id"]
        or succession["old_write_error"] != "origin_not_active"
    ):
        raise MultihostEvidenceError("invalid_succession_evidence")
    _uuid(succession["new_event_id"], "invalid_succession_evidence")
    if succession["new_lane_sequence"] != 1:
        raise MultihostEvidenceError("invalid_succession_evidence")
    _true(succession["old_high_water_preserved"], "invalid_succession_evidence")
    _true(succession["sync_resumed"], "invalid_succession_evidence")

    cluster = _closed(
        core["cluster"],
        {
            "body_snapshot_hash",
            "accepted_fence_hash",
            "same_resource_second_holder",
            "stale_replay",
            "different_resource",
            "ordinary_events_unaffected",
        },
        "invalid_cluster_evidence",
    )
    _hash(cluster["body_snapshot_hash"], "invalid_cluster_evidence")
    _hash(cluster["accepted_fence_hash"], "invalid_cluster_evidence")
    if (
        cluster["same_resource_second_holder"] != "fence_not_current"
        or cluster["stale_replay"] != "effect-truth-discrepancy"
        or cluster["different_resource"] != "verified"
    ):
        raise MultihostEvidenceError("invalid_cluster_evidence")
    _true(cluster["ordinary_events_unaffected"], "invalid_cluster_evidence")

    historical = _closed(
        core["historical"],
        {
            "provenance_hash",
            "validation",
            "identity_authority",
            "event_authority",
            "adoption_authority",
            "fence_authority",
        },
        "invalid_historical_evidence",
    )
    _hash(historical["provenance_hash"], "invalid_historical_evidence")
    if historical["validation"] != "verified" or any(
        historical[field] is not False
        for field in (
            "identity_authority",
            "event_authority",
            "adoption_authority",
            "fence_authority",
        )
    ):
        raise MultihostEvidenceError("historical_evidence_claims_authority")

    isolation = _closed(
        core["isolation"],
        {
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
        },
        "invalid_isolation_evidence",
    )
    for value in isolation.values():
        _true(value, "invalid_isolation_evidence")
    if core["schedule"] != list(SCHEDULE):
        raise MultihostEvidenceError("invalid_multihost_schedule")
    _safe_public_tree(core)
    _canonical(core, "invalid_multihost_receipt")
    return copy.deepcopy(dict(core))


def create_multihost_receipt(core: Mapping[str, Any]) -> dict[str, Any]:
    """Validate private-run reductions and content-address the public core."""

    normalized = _validate_receipt_core(core)
    digest = _digest(RECEIPT_DOMAIN, normalized)
    return {
        **normalized,
        "receipt_hash": digest.hex(),
        "receipt_id": f"dm:multihost-receipt:v1:{b64url(digest)}",
    }


def validate_multihost_receipt(value: Any) -> dict[str, Any]:
    """Validate a closed receipt and all cross-field invariants."""

    row = _closed(
        value,
        {
            "schema",
            "run_profile",
            "source_commit",
            "package",
            "authority",
            "processes",
            "partition",
            "sync",
            "adoption",
            "succession",
            "cluster",
            "historical",
            "isolation",
            "schedule",
            "receipt_hash",
            "receipt_id",
        },
        "invalid_multihost_receipt",
    )
    core = {
        key: copy.deepcopy(item)
        for key, item in row.items()
        if key not in {"receipt_hash", "receipt_id"}
    }
    normalized = _validate_receipt_core(core)
    digest = _digest(RECEIPT_DOMAIN, normalized)
    if (
        _hash(row["receipt_hash"], "invalid_multihost_receipt") != digest.hex()
        or row["receipt_id"] != f"dm:multihost-receipt:v1:{b64url(digest)}"
    ):
        raise MultihostEvidenceError("multihost_receipt_hash_mismatch")
    return copy.deepcopy(dict(row))


def event_set_hash(events: Sequence[Mapping[str, Any]]) -> str:
    """Hash a sorted immutable event set without arrival-order authority."""

    rows = sorted(
        (
            {
                "event_id": _uuid(event.get("event_id"), "invalid_event_set"),
                "content_hash": _hash(event.get("content_hash"), "invalid_event_set"),
            }
            for event in events
        ),
        key=lambda item: item["event_id"],
    )
    if len({row["event_id"] for row in rows}) != len(rows):
        raise MultihostEvidenceError("invalid_event_set")
    return hashlib.sha256(_canonical(rows, "invalid_event_set")).hexdigest()


__all__ = [
    "MAX_DOCUMENT_BYTES",
    "PROVENANCE_SCHEMA",
    "RECEIPT_SCHEMA",
    "RUN_PROFILE",
    "SCHEDULE",
    "MultihostEvidenceError",
    "create_multihost_receipt",
    "event_set_hash",
    "validate_cluster_provenance",
    "validate_multihost_receipt",
]
