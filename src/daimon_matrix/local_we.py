"""Deterministic evidence for one local Codex/Hermes plural-body Weave."""

from __future__ import annotations

import copy
import hashlib
import re
import stat
import uuid
from collections.abc import Mapping, Sequence
from typing import Any, Final, cast

from .canonical import CanonicalError, b64url, canonical_bytes
from .codex_body import (
    PLAN_DOMAIN as CODEX_PLAN_DOMAIN,
)
from .codex_body import (
    CodexBodyError,
    CodexBodyPlan,
)
from .codex_body import (
    validate_bootstrap as validate_codex_bootstrap,
)
from .codex_body import (
    validate_launch_receipt as validate_codex_launch_receipt,
)
from .codex_body import (
    verify_profile as verify_codex_profile,
)
from .hermes_body import (
    HermesBodyError,
    HermesBodyPlan,
)
from .hermes_body import (
    plan_id as hermes_plan_id,
)
from .hermes_body import (
    validate_bootstrap as validate_hermes_bootstrap,
)
from .hermes_body import (
    validate_launch_receipt as validate_hermes_launch_receipt,
)
from .hermes_body import (
    verify_profile as verify_hermes_profile,
)
from .ledger import Ledger, LedgerError
from .projections import ProjectionEngine, ProjectionError
from .sync import validate_receipt
from .weave import RootAuthority, verify_event

REPORT_SCHEMA: Final = "dm.local-we.validation/v1"
REPORT_DOMAIN: Final = b"daimon/local-we/validation/v1\x00"
EVENT_SET_DOMAIN: Final = b"daimon/local-we/event-set/v1\x00"
HEADS_DOMAIN: Final = b"daimon/local-we/heads/v1\x00"
MAX_SYNC_RECEIPTS: Final = 16

_HASH = re.compile(r"^[0-9a-f]{64}$")
_DERIVED = re.compile(r"^dm:[a-z0-9-]+:v[01]:[A-Za-z0-9_-]{43}$")
_BEING = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
_EMBODIMENT = re.compile(r"^embodiment:[A-Za-z0-9._:-]{1,240}$")
_INCARNATION = re.compile(r"^incarnation:[A-Za-z0-9._:-]{1,240}$")


class LocalWeError(ValueError):
    """The local plural-body proof is incomplete or internally inconsistent."""


def _canonical(value: Any, code: str) -> bytes:
    try:
        return canonical_bytes(value)
    except CanonicalError as exception:
        raise LocalWeError(code) from exception


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LocalWeError(code)
    return value


def _text(value: Any, code: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value.encode()) > maximum:
        raise LocalWeError(code)
    _canonical(value, code)
    return value


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise LocalWeError(code)
    return value


def _uint(value: Any, code: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 2**53 - 1
    ):
        raise LocalWeError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    text = _text(value, code, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exception:
        raise LocalWeError(code) from exception
    if parsed.version != 4 or str(parsed) != text:
        raise LocalWeError(code)
    return text


def _derived(value: Any, code: str, *, prefix: str | None = None) -> str:
    text = _text(value, code, maximum=192)
    if _DERIVED.fullmatch(text) is None or (
        prefix is not None and not text.startswith(prefix)
    ):
        raise LocalWeError(code)
    return text


def _digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(
        domain + _canonical(value, "invalid_local_we_value")
    ).hexdigest()


def _report_id(core: Mapping[str, Any]) -> str:
    return "dm:local-we-validation:v1:" + b64url(
        hashlib.sha256(
            REPORT_DOMAIN + _canonical(core, "invalid_local_we_report")
        ).digest()
    )


def _member_evidence(
    authority: RootAuthority,
    origin: Mapping[str, str],
    bootstrap: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        member = authority.validate_origin(origin, require_active=True)
    except Exception as exception:
        raise LocalWeError("body_origin_not_authorized") from exception
    if (
        bootstrap["being_ref"] != authority.manifest.being_ref
        or any(
            bootstrap[field] != origin[field]
            for field in ("body_ref", "embodiment_id", "incarnation_id")
        )
        or any(
            member[field] != origin[field]
            for field in ("body_ref", "embodiment_id", "incarnation_id")
        )
    ):
        raise LocalWeError("body_manifest_binding_mismatch")
    credential_id = cast(str, member["embodiment_credential_id"])
    authorization_id = cast(str, member["incarnation_authorization_id"])
    credential = authority.credentials.get(credential_id)
    authorization = authority.incarnations.get(authorization_id)
    if not isinstance(credential, Mapping) or not isinstance(authorization, Mapping):
        raise LocalWeError("body_authority_evidence_missing")
    body = cast(Mapping[str, Any], credential["body"])
    principals = cast(Sequence[Mapping[str, Any]], body["transport_principals"])
    matching = [
        item
        for item in principals
        if item.get("principal_id") == origin["principal_id"]
    ]
    if len(matching) != 1:
        raise LocalWeError("body_transport_principal_mismatch")
    return {
        "embodiment_credential_id": credential_id,
        "incarnation_authorization_id": authorization_id,
        "signing_key_id": body["signing_key"]["key_id"],
        "encryption_key_id": body["encryption_key"]["key_id"],
        "transport_key_ids": sorted(item["key"]["key_id"] for item in principals),
    }


def _assert_distinct_storage(left: Ledger, right: Ledger) -> None:
    try:
        left.initialize()
        right.initialize()
        left_path = left.path.resolve(strict=True)
        right_path = right.path.resolve(strict=True)
        left_info = left_path.stat()
        right_info = right_path.stat()
    except (LedgerError, OSError) as exception:
        raise LocalWeError("ledger_storage_unavailable") from exception
    if left_path == right_path:
        raise LocalWeError("shared_writable_ledger")
    if (
        not stat.S_ISREG(left_info.st_mode)
        or not stat.S_ISREG(right_info.st_mode)
        or (left_info.st_dev, left_info.st_ino)
        == (right_info.st_dev, right_info.st_ino)
    ):
        raise LocalWeError("shared_writable_ledger")


def _assert_distinct_profiles(left: CodexBodyPlan, right: HermesBodyPlan) -> None:
    try:
        left_root = left.profile_root.resolve(strict=True)
        right_root = right.profile_root.resolve(strict=True)
        left_info = left_root.stat()
        right_info = right_root.stat()
    except OSError as exception:
        raise LocalWeError("body_profile_unavailable") from exception
    if (
        left_root == right_root
        or not stat.S_ISDIR(left_info.st_mode)
        or not stat.S_ISDIR(right_info.st_mode)
        or (left_info.st_dev, left_info.st_ino)
        == (right_info.st_dev, right_info.st_ino)
    ):
        raise LocalWeError("shared_body_profile")


def _projection_entry(
    projection: Mapping[str, Any], target_event_id: str, code: str
) -> Mapping[str, Any]:
    matches = [
        item
        for item in cast(Sequence[Mapping[str, Any]], projection["entries"])
        if item["event_id"] == target_event_id
    ]
    if len(matches) != 1:
        raise LocalWeError(code)
    return matches[0]


def _body_report(
    *,
    harness: str,
    origin: Mapping[str, str],
    authority_evidence: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    profile_id: str,
    launch_receipt_id: str,
    launch_high_water: str,
    ledger_heads_hash: str,
    ledger_state_hash: str,
    projection: Mapping[str, Any],
    entry: Mapping[str, Any],
    decision: str,
) -> dict[str, Any]:
    return {
        "harness": harness,
        "body_ref": origin["body_ref"],
        "embodiment_id": origin["embodiment_id"],
        "incarnation_id": origin["incarnation_id"],
        "principal_id": origin["principal_id"],
        **copy.deepcopy(dict(authority_evidence)),
        "matrix_session_id": bootstrap["matrix_session_id"],
        "matrix_high_water": launch_high_water,
        "capability_set_hash": bootstrap["capability_set_hash"],
        "profile_id": profile_id,
        "launch_receipt_id": launch_receipt_id,
        "ledger_heads_hash": ledger_heads_hash,
        "ledger_state_hash": ledger_state_hash,
        "projection_hash": projection["projection_hash"],
        "decision": decision,
        "decision_event_id": entry["decision_event_id"],
        "state": entry["state"],
        "remote_decision_event_ids": copy.deepcopy(entry["remote_decision_event_ids"]),
    }


def create_local_we_report(
    *,
    authority: RootAuthority,
    codex_plan: CodexBodyPlan,
    codex_launch_receipt: Mapping[str, Any],
    codex_ledger: Ledger,
    codex_projection: Mapping[str, Any],
    hermes_plan: HermesBodyPlan,
    hermes_launch_receipt: Mapping[str, Any],
    hermes_ledger: Ledger,
    hermes_projection: Mapping[str, Any],
    sync_receipts: Sequence[Mapping[str, Any]],
    target_event_id: str,
    observed_at_ms: int,
) -> dict[str, Any]:
    """Verify the full synthetic proof and return only bounded public evidence."""

    if authority.manifest.trust_mode != "root-bound":
        raise LocalWeError("root_bound_authority_required")
    target_event_id = _uuid(target_event_id, "invalid_target_event_id")
    _assert_distinct_storage(codex_ledger, hermes_ledger)
    if (
        codex_ledger.authority.manifest.digest != authority.manifest.digest
        or hermes_ledger.authority.manifest.digest != authority.manifest.digest
    ):
        raise LocalWeError("manifest_hash_mismatch")

    try:
        codex_bootstrap = validate_codex_bootstrap(codex_plan.value["bootstrap"])
        hermes_bootstrap = validate_hermes_bootstrap(hermes_plan.value["bootstrap"])
        codex_launch = validate_codex_launch_receipt(codex_launch_receipt)
        hermes_launch = validate_hermes_launch_receipt(
            hermes_launch_receipt, hermes_plan
        )
        codex_profile = verify_codex_profile(codex_plan)
        hermes_profile = verify_hermes_profile(hermes_plan)
    except (CodexBodyError, HermesBodyError) as exception:
        raise LocalWeError("body_launch_evidence_invalid") from exception
    codex_origin = copy.deepcopy(codex_ledger.local_origin)
    hermes_origin = copy.deepcopy(hermes_ledger.local_origin)
    codex_authority = _member_evidence(authority, codex_origin, codex_bootstrap)
    hermes_authority = _member_evidence(authority, hermes_origin, hermes_bootstrap)

    codex_binding = cast(Mapping[str, Any], codex_launch["matrix_binding"])
    if any(
        codex_binding[field] != codex_bootstrap[field]
        for field in (
            "being_ref",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "matrix_session_id",
        )
    ):
        raise LocalWeError("codex_launch_binding_mismatch")
    expected_codex_plan_hash = hashlib.sha256(
        CODEX_PLAN_DOMAIN + _canonical(codex_plan.value, "invalid_codex_body_plan")
    ).hexdigest()
    if (
        codex_launch["plan_hash"] != expected_codex_plan_hash
        or codex_launch["profile_id"] != codex_profile["profile_id"]
    ):
        raise LocalWeError("codex_launch_binding_mismatch")
    if hermes_launch["plan_id"] != hermes_plan_id(hermes_plan.value):
        raise LocalWeError("hermes_launch_binding_mismatch")
    if (
        hermes_launch["profile_id"] != hermes_profile["profile_id"]
        or hermes_launch["matrix_package"] != hermes_profile["matrix_package"]
    ):
        raise LocalWeError("hermes_launch_binding_mismatch")
    _assert_distinct_profiles(codex_plan, hermes_plan)

    distinct_values = (
        (codex_origin["body_ref"], hermes_origin["body_ref"]),
        (codex_origin["embodiment_id"], hermes_origin["embodiment_id"]),
        (codex_origin["incarnation_id"], hermes_origin["incarnation_id"]),
        (codex_origin["principal_id"], hermes_origin["principal_id"]),
        (
            codex_authority["embodiment_credential_id"],
            hermes_authority["embodiment_credential_id"],
        ),
        (codex_authority["signing_key_id"], hermes_authority["signing_key_id"]),
        (
            codex_authority["encryption_key_id"],
            hermes_authority["encryption_key_id"],
        ),
        (
            codex_bootstrap["matrix_session_id"],
            hermes_bootstrap["matrix_session_id"],
        ),
        (
            codex_bootstrap["capability_set_hash"],
            hermes_bootstrap["capability_set_hash"],
        ),
        (codex_launch["profile_id"], hermes_launch["profile_id"]),
    )
    if any(left == right for left, right in distinct_values) or set(
        codex_authority["transport_key_ids"]
    ).intersection(hermes_authority["transport_key_ids"]):
        raise LocalWeError("body_custody_not_distinct")
    if codex_bootstrap["matrix_high_water"] != hermes_bootstrap["matrix_high_water"]:
        raise LocalWeError("initial_high_water_mismatch")

    codex_events = codex_ledger.events(include_incomplete=False)
    hermes_events = hermes_ledger.events(include_incomplete=False)
    if _canonical(codex_events, "ledger_not_converged") != _canonical(
        hermes_events, "ledger_not_converged"
    ):
        raise LocalWeError("ledger_not_converged")
    if not codex_events:
        raise LocalWeError("local_we_has_no_events")
    for event in codex_events:
        try:
            verify_event(event, authority)
        except Exception as exception:
            raise LocalWeError("local_we_event_invalid") from exception
    authored = {event["origin"]["embodiment_id"] for event in codex_events}
    if not {
        codex_origin["embodiment_id"],
        hermes_origin["embodiment_id"],
    }.issubset(authored):
        raise LocalWeError("both_bodies_must_author")

    try:
        accepted_codex_projection = ProjectionEngine.verify(codex_projection)
        accepted_hermes_projection = ProjectionEngine.verify(hermes_projection)
    except ProjectionError as exception:
        raise LocalWeError("projection_evidence_invalid") from exception
    fresh_codex_projection = ProjectionEngine(codex_ledger).snapshot()
    fresh_hermes_projection = ProjectionEngine(hermes_ledger).snapshot()
    if _canonical(
        accepted_codex_projection, "projection_evidence_invalid"
    ) != _canonical(
        fresh_codex_projection, "projection_evidence_invalid"
    ) or _canonical(
        accepted_hermes_projection, "projection_evidence_invalid"
    ) != _canonical(fresh_hermes_projection, "projection_evidence_invalid"):
        raise LocalWeError("projection_ledger_mismatch")
    for projection, origin in (
        (accepted_codex_projection, codex_origin),
        (accepted_hermes_projection, hermes_origin),
    ):
        if (
            projection["being_ref"] != authority.manifest.being_ref
            or projection["manifest_hash"] != authority.manifest.digest
            or projection["local_embodiment_id"] != origin["embodiment_id"]
        ):
            raise LocalWeError("projection_binding_mismatch")

    codex_entry = _projection_entry(
        accepted_codex_projection, target_event_id, "codex_target_missing"
    )
    hermes_entry = _projection_entry(
        accepted_hermes_projection, target_event_id, "hermes_target_missing"
    )
    if codex_entry["state"] != "adopted" or hermes_entry["state"] != "rejected":
        raise LocalWeError("independent_adoption_not_proven")
    codex_decision_id = cast(str, codex_entry["decision_event_id"])
    hermes_decision_id = cast(str, hermes_entry["decision_event_id"])
    if (
        hermes_decision_id not in codex_entry["remote_decision_event_ids"]
        or codex_decision_id not in hermes_entry["remote_decision_event_ids"]
    ):
        raise LocalWeError("remote_decision_evidence_missing")
    by_id = {event["event_id"]: event for event in codex_events}
    for event_id, origin, decision in (
        (codex_decision_id, codex_origin, "adopt"),
        (hermes_decision_id, hermes_origin, "reject"),
    ):
        selected_event = by_id.get(event_id)
        if (
            selected_event is None
            or selected_event["kind"] != "adoption.decided"
            or selected_event["origin"] != origin
            or selected_event["payload"]["target_event_id"] != target_event_id
            or selected_event["payload"]["decision"] != decision
        ):
            raise LocalWeError("local_decision_binding_mismatch")

    if not 2 <= len(sync_receipts) <= MAX_SYNC_RECEIPTS:
        raise LocalWeError("sync_receipt_coverage_missing")
    directions: set[tuple[str, str]] = set()
    sync_rows: list[dict[str, Any]] = []
    seen_requests: set[str] = set()
    for raw in sync_receipts:
        try:
            receipt = validate_receipt(raw, authority)
        except Exception as exception:
            raise LocalWeError("sync_receipt_invalid") from exception
        sender = receipt["sender"]["embodiment_id"]
        receiver = receipt["receiver"]["embodiment_id"]
        if {sender, receiver} != {
            codex_origin["embodiment_id"],
            hermes_origin["embodiment_id"],
        }:
            raise LocalWeError("sync_receipt_body_mismatch")
        if receipt["request_id"] in seen_requests:
            raise LocalWeError("sync_request_duplicated")
        seen_requests.add(receipt["request_id"])
        directions.add((sender, receiver))
        sync_rows.append(
            {
                "sender_embodiment_id": sender,
                "receiver_embodiment_id": receiver,
                "request_id": receipt["request_id"],
                "page_hash": receipt["page_hash"],
                "receipt_hash": receipt["receipt_hash"],
                "received": receipt["received"],
                "inserted": receipt["inserted"],
                "replayed": receipt["replayed"],
            }
        )
    expected_directions = {
        (codex_origin["embodiment_id"], hermes_origin["embodiment_id"]),
        (hermes_origin["embodiment_id"], codex_origin["embodiment_id"]),
    }
    if directions != expected_directions:
        raise LocalWeError("bidirectional_sync_not_proven")

    event_set_hash = _digest(EVENT_SET_DOMAIN, codex_events)
    heads_hash = _digest(HEADS_DOMAIN, codex_ledger.heads())
    if heads_hash != _digest(HEADS_DOMAIN, hermes_ledger.heads()):
        raise LocalWeError("ledger_heads_not_converged")
    bodies = [
        _body_report(
            harness="codex",
            origin=codex_origin,
            authority_evidence=codex_authority,
            bootstrap=codex_bootstrap,
            profile_id=cast(str, codex_launch["profile_id"]),
            launch_receipt_id=cast(str, codex_launch["receipt_id"]),
            launch_high_water=cast(str, codex_binding["matrix_high_water"]),
            ledger_heads_hash=heads_hash,
            ledger_state_hash=event_set_hash,
            projection=accepted_codex_projection,
            entry=codex_entry,
            decision="adopt",
        ),
        _body_report(
            harness="hermes",
            origin=hermes_origin,
            authority_evidence=hermes_authority,
            bootstrap=hermes_bootstrap,
            profile_id=cast(str, hermes_launch["profile_id"]),
            launch_receipt_id=cast(str, hermes_launch["launch_receipt_id"]),
            launch_high_water=cast(str, hermes_launch["matrix_high_water"]),
            ledger_heads_hash=heads_hash,
            ledger_state_hash=event_set_hash,
            projection=accepted_hermes_projection,
            entry=hermes_entry,
            decision="reject",
        ),
    ]
    core = {
        "schema": REPORT_SCHEMA,
        "being_ref": authority.manifest.being_ref,
        "control_head": authority.manifest.value["control_head"],
        "manifest_hash": authority.manifest.digest,
        "observed_at_ms": _uint(observed_at_ms, "invalid_observed_time"),
        "bodies": bodies,
        "sync": sorted(
            sync_rows,
            key=lambda row: (
                row["sender_embodiment_id"],
                row["receiver_embodiment_id"],
                row["request_id"],
            ),
        ),
        "event_set_hash": event_set_hash,
        "target_event_id": target_event_id,
        "storage_isolation": {
            "capability_sets_distinct": True,
            "credentials_distinct": True,
            "encryption_keys_distinct": True,
            "incarnations_distinct": True,
            "ledger_files_distinct": True,
            "matrix_sessions_distinct": True,
            "principals_distinct": True,
            "profile_roots_distinct": True,
            "signing_keys_distinct": True,
            "transport_keys_distinct": True,
        },
    }
    return validate_local_we_report({**core, "report_id": _report_id(core)})


def validate_local_we_report(value: Any) -> dict[str, Any]:
    """Validate the closed path-free report without trusting filesystem state."""

    row = _closed(
        value,
        {
            "being_ref",
            "bodies",
            "control_head",
            "event_set_hash",
            "manifest_hash",
            "observed_at_ms",
            "report_id",
            "schema",
            "storage_isolation",
            "sync",
            "target_event_id",
        },
        "invalid_local_we_report",
    )
    if row["schema"] != REPORT_SCHEMA:
        raise LocalWeError("unsupported_local_we_report")
    if (
        _BEING.fullmatch(_text(row["being_ref"], "invalid_being_ref", maximum=128))
        is None
    ):
        raise LocalWeError("invalid_being_ref")
    _derived(row["control_head"], "invalid_control_head", prefix="dm:identity:v1:")
    _hash(row["manifest_hash"], "invalid_manifest_hash")
    _hash(row["event_set_hash"], "invalid_event_set_hash")
    _uint(row["observed_at_ms"], "invalid_observed_time")
    _uuid(row["target_event_id"], "invalid_target_event_id")

    isolation_fields = {
        "capability_sets_distinct",
        "credentials_distinct",
        "encryption_keys_distinct",
        "incarnations_distinct",
        "ledger_files_distinct",
        "matrix_sessions_distinct",
        "principals_distinct",
        "profile_roots_distinct",
        "signing_keys_distinct",
        "transport_keys_distinct",
    }
    isolation = _closed(
        row["storage_isolation"], isolation_fields, "invalid_storage_isolation"
    )
    if any(value is not True for value in isolation.values()):
        raise LocalWeError("storage_isolation_not_proven")

    bodies = row["bodies"]
    if not isinstance(bodies, list) or len(bodies) != 2:
        raise LocalWeError("invalid_local_we_bodies")
    body_fields = {
        "body_ref",
        "capability_set_hash",
        "decision",
        "decision_event_id",
        "embodiment_credential_id",
        "embodiment_id",
        "encryption_key_id",
        "harness",
        "incarnation_authorization_id",
        "incarnation_id",
        "launch_receipt_id",
        "ledger_heads_hash",
        "ledger_state_hash",
        "matrix_high_water",
        "matrix_session_id",
        "principal_id",
        "profile_id",
        "projection_hash",
        "remote_decision_event_ids",
        "signing_key_id",
        "state",
        "transport_key_ids",
    }
    accepted: list[dict[str, Any]] = []
    for item in bodies:
        body = _closed(item, body_fields, "invalid_local_we_body")
        harness = body["harness"]
        if harness not in {"codex", "hermes"}:
            raise LocalWeError("invalid_local_we_harness")
        _text(body["body_ref"], "invalid_body_ref")
        if (
            _EMBODIMENT.fullmatch(_text(body["embodiment_id"], "invalid_embodiment_id"))
            is None
            or _INCARNATION.fullmatch(
                _text(body["incarnation_id"], "invalid_incarnation_id")
            )
            is None
        ):
            raise LocalWeError("invalid_body_identity")
        _text(body["principal_id"], "invalid_principal_id", maximum=128)
        for field in (
            "embodiment_credential_id",
            "incarnation_authorization_id",
            "encryption_key_id",
            "matrix_session_id",
            "profile_id",
            "signing_key_id",
        ):
            _derived(body[field], "invalid_body_evidence")
        expected_launch = (
            "dm:codex-launch-receipt:v1:"
            if harness == "codex"
            else "dm:hermes-launch:v1:"
        )
        _derived(
            body["launch_receipt_id"],
            "invalid_launch_receipt_id",
            prefix=expected_launch,
        )
        for field in (
            "capability_set_hash",
            "ledger_heads_hash",
            "ledger_state_hash",
            "matrix_high_water",
            "projection_hash",
        ):
            _hash(body[field], "invalid_body_hash")
        expected = (
            ("adopt", "adopted") if harness == "codex" else ("reject", "rejected")
        )
        if (body["decision"], body["state"]) != expected:
            raise LocalWeError("invalid_local_decision")
        _uuid(body["decision_event_id"], "invalid_decision_event_id")
        for field in ("transport_key_ids", "remote_decision_event_ids"):
            values = body[field]
            if (
                not isinstance(values, list)
                or not values
                or values != sorted(set(values))
            ):
                raise LocalWeError("invalid_body_evidence_list")
        for key_id in body["transport_key_ids"]:
            _derived(key_id, "invalid_transport_key")
        for event_id in body["remote_decision_event_ids"]:
            _uuid(event_id, "invalid_remote_decision")
        accepted.append(copy.deepcopy(dict(body)))
    if [item["harness"] for item in accepted] != ["codex", "hermes"]:
        raise LocalWeError("local_we_bodies_not_sorted")
    left, right = accepted
    distinct_fields = (
        "body_ref",
        "capability_set_hash",
        "embodiment_credential_id",
        "embodiment_id",
        "encryption_key_id",
        "incarnation_authorization_id",
        "incarnation_id",
        "launch_receipt_id",
        "matrix_session_id",
        "principal_id",
        "profile_id",
        "projection_hash",
        "signing_key_id",
    )
    if any(left[field] == right[field] for field in distinct_fields):
        raise LocalWeError("body_evidence_not_distinct")
    if (
        left["ledger_heads_hash"] != right["ledger_heads_hash"]
        or left["ledger_state_hash"] != right["ledger_state_hash"]
        or left["ledger_state_hash"] != row["event_set_hash"]
        or left["matrix_high_water"] != right["matrix_high_water"]
        or right["decision_event_id"] not in left["remote_decision_event_ids"]
        or left["decision_event_id"] not in right["remote_decision_event_ids"]
    ):
        raise LocalWeError("convergence_or_decision_evidence_mismatch")

    sync = row["sync"]
    if not isinstance(sync, list) or not 2 <= len(sync) <= MAX_SYNC_RECEIPTS:
        raise LocalWeError("invalid_sync_evidence")
    sync_fields = {
        "inserted",
        "page_hash",
        "received",
        "receiver_embodiment_id",
        "receipt_hash",
        "replayed",
        "request_id",
        "sender_embodiment_id",
    }
    accepted_sync: list[dict[str, Any]] = []
    for item in sync:
        evidence = _closed(item, sync_fields, "invalid_sync_evidence")
        for field in ("sender_embodiment_id", "receiver_embodiment_id"):
            if (
                _EMBODIMENT.fullmatch(_text(evidence[field], "invalid_sync_embodiment"))
                is None
            ):
                raise LocalWeError("invalid_sync_embodiment")
        _uuid(evidence["request_id"], "invalid_sync_request_id")
        _hash(evidence["page_hash"], "invalid_sync_hash")
        _hash(evidence["receipt_hash"], "invalid_sync_hash")
        received = _uint(evidence["received"], "invalid_sync_count")
        inserted = _uint(evidence["inserted"], "invalid_sync_count")
        replayed = _uint(evidence["replayed"], "invalid_sync_count")
        if received == 0 or inserted + replayed != received:
            raise LocalWeError("invalid_sync_count")
        accepted_sync.append(copy.deepcopy(dict(evidence)))
    if accepted_sync != sorted(
        accepted_sync,
        key=lambda item: (
            item["sender_embodiment_id"],
            item["receiver_embodiment_id"],
            item["request_id"],
        ),
    ):
        raise LocalWeError("sync_evidence_not_sorted")
    directions = {
        (item["sender_embodiment_id"], item["receiver_embodiment_id"])
        for item in accepted_sync
    }
    if directions != {
        (left["embodiment_id"], right["embodiment_id"]),
        (right["embodiment_id"], left["embodiment_id"]),
    }:
        raise LocalWeError("bidirectional_sync_not_proven")

    core = {key: copy.deepcopy(item) for key, item in row.items() if key != "report_id"}
    if row["report_id"] != _report_id(core):
        raise LocalWeError("local_we_report_id_mismatch")
    _canonical(row, "invalid_local_we_report")
    return copy.deepcopy(dict(row))


__all__ = [
    "EVENT_SET_DOMAIN",
    "HEADS_DOMAIN",
    "REPORT_DOMAIN",
    "REPORT_SCHEMA",
    "LocalWeError",
    "create_local_we_report",
    "validate_local_we_report",
]
