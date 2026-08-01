"""Signed GitHub claim commands and append-only automation receipts.

The pure functions in this module do not call GitHub. Issue comments are the
public event log; callers provide comment metadata, the explicit principal
registry, and a trusted UTC clock.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import re
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


COMMAND_SCHEMA = "daimon-claim-command/v0"
RECEIPT_SCHEMA = "daimon-claim-receipt/v0"
REGISTRY_SCHEMA = "daimon-coordination-principals/v0"
COMMAND_MARKER = COMMAND_SCHEMA
RECEIPT_MARKER = RECEIPT_SCHEMA
COMMAND_DOMAIN = b"daimon/github-coordination-command/v0\x00"
RECEIPT_DOMAIN = b"daimon/github-coordination-receipt/v0\x00"
SESSION_DOMAIN = b"daimon/github-coordination-session/v0\x00"
MAX_LEASE_SECONDS = 24 * 60 * 60
MAX_CLOCK_SKEW = dt.timedelta(minutes=10)
ACTIVE_STATES = frozenset({"in_progress", "in_review"})
TERMINAL_STATES = frozenset({"ready", "done"})
COMMAND_ACTIONS = frozenset({"claim", "heartbeat", "review", "release"})
RECEIPT_DECISIONS = frozenset({"accepted", "rejected", "expired"})

_COMMAND_BLOCK = re.compile(
    r"<!--\s*daimon-claim-command/v0\s*\n(?P<payload>.*?)\s*\n-->",
    re.DOTALL,
)
_RECEIPT_BLOCK = re.compile(
    r"<!--\s*daimon-claim-receipt/v0\s*\n(?P<payload>.*?)\s*\n-->",
    re.DOTALL,
)
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PRINCIPAL = re.compile(r"^[A-Za-z0-9_.:@/-]+$")
_RESOURCE = re.compile(r"^(issue|path|service|project|protocol):\S+$")
_BRANCH = re.compile(r"^[^\s~^:?*\[\\]+(?:/[^\s~^:?*\[\\]+)*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")

_COMMAND_BODY_KEYS = frozenset(
    {
        "schema",
        "action",
        "command_id",
        "claim_id",
        "issue",
        "principal",
        "session_id",
        "session_key",
        "at",
        "lease_seconds",
        "resources",
        "branch",
        "pull_request",
        "previous_receipt_id",
        "previous_receipt_hash",
        "note",
    }
)
_COMMAND_WRAPPER_KEYS = frozenset({"body", "signature"})
_RECEIPT_BODY_KEYS = frozenset(
    {
        "schema",
        "decision",
        "action",
        "reason",
        "command_id",
        "claim_id",
        "issue",
        "principal",
        "session_id",
        "state",
        "at",
        "lease_until",
        "resources",
        "branch",
        "pull_request",
        "previous_receipt_id",
        "previous_receipt_hash",
        "workflow_sha",
    }
)
_RECEIPT_WRAPPER_KEYS = frozenset({"body", "receipt_id", "receipt_hash"})


class CoordinationError(ValueError):
    """A command, receipt, registry, or state transition is invalid."""


@dataclasses.dataclass(frozen=True)
class IssueRef:
    repository: str
    number: int

    @property
    def resource(self) -> str:
        return f"issue:{self.repository}#{self.number}"


@dataclasses.dataclass(frozen=True)
class SessionKey:
    kid: str
    public_key: bytes


@dataclasses.dataclass(frozen=True)
class Command:
    body: Mapping[str, Any]
    command_id: str
    claim_id: str
    action: str
    issue: IssueRef
    principal: str
    session_id: str
    session_key: SessionKey
    at: dt.datetime
    lease_seconds: int | None
    resources: tuple[str, ...]
    branch: str | None
    pull_request: int | None
    previous_receipt_id: str | None
    previous_receipt_hash: str | None
    note: str | None
    comment_id: int | None = None
    comment_author: str | None = None


@dataclasses.dataclass(frozen=True)
class Receipt:
    body: Mapping[str, Any]
    receipt_id: str
    receipt_hash: str
    decision: str
    action: str
    reason: str
    command_id: str | None
    claim_id: str
    issue: IssueRef
    principal: str
    session_id: str
    state: str
    at: dt.datetime
    lease_until: dt.datetime | None
    resources: tuple[str, ...]
    branch: str | None
    pull_request: int | None
    previous_receipt_id: str | None
    previous_receipt_hash: str | None
    workflow_sha: str
    comment_id: int | None = None
    comment_author: str | None = None

    def is_live(self, now: dt.datetime) -> bool:
        return (
            self.state in ACTIVE_STATES
            and self.lease_until is not None
            and self.lease_until > now
        )


@dataclasses.dataclass(frozen=True)
class Finding:
    code: str
    message: str


def _validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise CoordinationError("canonical JSON exceeds depth 16")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise CoordinationError("canonical JSON integer is outside safe range")
        return
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise CoordinationError("coordination strings must be ASCII") from exc
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoordinationError("canonical JSON object keys must be strings")
            _validate_json_value(key, depth + 1)
            _validate_json_value(item, depth + 1)
        return
    raise CoordinationError("unsupported canonical JSON value")


def canonical_json(value: Any) -> bytes:
    """Return the closed protocol canonical JSON subset used by coordination."""
    _validate_json_value(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise CoordinationError("value is not canonical JSON data") from exc
    return rendered.encode("ascii")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: Any, *, field: str, size: int) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise CoordinationError(f"{field} must be canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise CoordinationError(f"{field} must be canonical base64url") from exc
    if len(decoded) != size or _b64url_encode(decoded) != value:
        raise CoordinationError(f"{field} must encode exactly {size} bytes")
    return decoded


def _uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise CoordinationError(f"{field} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CoordinationError(f"{field} must be a UUID") from exc
    if str(parsed) != value or parsed.version != 4:
        raise CoordinationError(f"{field} must be a canonical lowercase UUIDv4")
    return value


def parse_timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CoordinationError(f"{field} must be RFC 3339 UTC ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CoordinationError(f"{field} is not a valid timestamp") from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise CoordinationError(f"{field} must use UTC")
    return parsed


def format_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != dt.timedelta(0):
        raise CoordinationError("timestamp must be timezone-aware UTC")
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _issue(value: Any) -> IssueRef:
    if not isinstance(value, Mapping) or set(value) != {"repository", "number"}:
        raise CoordinationError("issue must contain exactly repository and number")
    repository = value["repository"]
    number = value["number"]
    if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
        raise CoordinationError("issue.repository must be owner/name")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise CoordinationError("issue.number must be a positive integer")
    return IssueRef(repository, number)


def _branch(value: Any) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > 255
        or not _BRANCH.fullmatch(value)
        or value.startswith(("/", "."))
        or value.endswith(("/", "."))
        or ".." in value
        or "@{" in value
        or "//" in value
        or any(part.startswith(".") or part.endswith(".lock") for part in value.split("/"))
    ):
        raise CoordinationError("branch is not a safe Git ref name")
    return value


def _resources(value: Any, issue: IssueRef) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 64
        or any(
            not isinstance(item, str)
            or len(item) > 256
            or not _RESOURCE.fullmatch(item)
            for item in value
        )
    ):
        raise CoordinationError("resources must be 1..64 typed resource strings")
    if value != sorted(value) or len(set(value)) != len(value):
        raise CoordinationError("resources must be sorted and duplicate-free")
    if issue.resource not in value:
        raise CoordinationError(f"resources must include {issue.resource}")
    return tuple(value)


def _receipt_reference(value: Any, hash_value: Any, *, field: str) -> None:
    if value is None and hash_value is None:
        return
    if not isinstance(value, str) or not value.startswith("dm:claim-receipt:v0:"):
        raise CoordinationError(f"{field}_id is not a receipt ID")
    suffix = value.removeprefix("dm:claim-receipt:v0:")
    _b64url_decode(suffix, field=f"{field}_id", size=32)
    _b64url_decode(hash_value, field=f"{field}_hash", size=32)
    if suffix != hash_value:
        raise CoordinationError(f"{field} ID/hash mismatch")


def key_descriptor(public_key: bytes) -> dict[str, str]:
    if len(public_key) != 32:
        raise CoordinationError("Ed25519 public key must be 32 bytes")
    descriptor = {"alg": "Ed25519", "public_key": _b64url_encode(public_key)}
    digest = hashlib.sha256(canonical_json(descriptor)).digest()
    return {**descriptor, "kid": "dm:coord-key:v0:" + _b64url_encode(digest)}


def session_id_for(descriptor: Mapping[str, Any]) -> str:
    parsed = _session_key(descriptor)
    core = {
        "alg": "Ed25519",
        "kid": parsed.kid,
        "public_key": _b64url_encode(parsed.public_key),
    }
    digest = hashlib.sha256(SESSION_DOMAIN + canonical_json(core)).digest()
    return "dm:coord-session:v0:" + _b64url_encode(digest)


def _session_key(value: Any) -> SessionKey:
    if not isinstance(value, Mapping) or set(value) != {"alg", "kid", "public_key"}:
        raise CoordinationError("session_key must be a closed Ed25519 descriptor")
    if value["alg"] != "Ed25519":
        raise CoordinationError("session_key algorithm must be Ed25519")
    public_key = _b64url_decode(value["public_key"], field="session_key.public_key", size=32)
    expected = key_descriptor(public_key)["kid"]
    if value["kid"] != expected:
        raise CoordinationError("session_key.kid does not match its public key")
    return SessionKey(expected, public_key)


def _signature(value: Any, key: SessionKey, body: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != {"alg", "kid", "role", "value"}:
        raise CoordinationError("signature must be a closed signature record")
    if value["alg"] != "Ed25519" or value["kid"] != key.kid:
        raise CoordinationError("signature key does not match session key")
    if value["role"] != "claim-attestation":
        raise CoordinationError("signature role must be claim-attestation")
    signature = _b64url_decode(value["value"], field="signature.value", size=64)
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature, COMMAND_DOMAIN + canonical_json(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise CoordinationError("invalid detached session signature") from exc


def validate_command(
    raw: Mapping[str, Any],
    *,
    comment_id: int | None = None,
    comment_author: str | None = None,
) -> Command:
    if not isinstance(raw, Mapping) or set(raw) != _COMMAND_WRAPPER_KEYS:
        raise CoordinationError("command wrapper must contain exactly body and signature")
    body = raw["body"]
    if not isinstance(body, Mapping) or set(body) != _COMMAND_BODY_KEYS:
        raise CoordinationError("command body is not a closed v0 body")
    if body["schema"] != COMMAND_SCHEMA:
        raise CoordinationError(f"command schema must be {COMMAND_SCHEMA}")
    action = body["action"]
    if action not in COMMAND_ACTIONS:
        raise CoordinationError(f"unsupported command action {action!r}")
    issue = _issue(body["issue"])
    principal = body["principal"]
    if (
        not isinstance(principal, str)
        or not 1 <= len(principal) <= 128
        or not _PRINCIPAL.fullmatch(principal)
    ):
        raise CoordinationError("principal contains unsupported characters")
    session_key = _session_key(body["session_key"])
    expected_session = session_id_for(body["session_key"])
    if body["session_id"] != expected_session:
        raise CoordinationError("session_id does not match session_key")
    at = parse_timestamp(body["at"], "at")
    lease_seconds = body["lease_seconds"]
    if action in {"claim", "heartbeat", "review"}:
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 60 <= lease_seconds <= MAX_LEASE_SECONDS
        ):
            raise CoordinationError("active commands require lease_seconds in 60..86400")
    elif lease_seconds is not None:
        raise CoordinationError("release requires null lease_seconds")
    branch = _branch(body["branch"])
    if branch is None:
        raise CoordinationError("all claim commands require their immutable branch")
    pull_request = body["pull_request"]
    if pull_request is not None and (
        isinstance(pull_request, bool)
        or not isinstance(pull_request, int)
        or pull_request < 1
    ):
        raise CoordinationError("pull_request must be positive or null")
    if action == "review" and pull_request is None:
        raise CoordinationError("review requires pull_request")
    if action in {"claim", "heartbeat", "release"} and pull_request is not None:
        raise CoordinationError(f"{action} requires null pull_request")
    note = body["note"]
    if note is not None and (
        not isinstance(note, str)
        or len(note) > 500
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in note)
    ):
        raise CoordinationError("note must be null or at most 500 printable ASCII characters")
    previous_id = body["previous_receipt_id"]
    previous_hash = body["previous_receipt_hash"]
    if (previous_id is None) != (previous_hash is None):
        raise CoordinationError("previous receipt ID/hash nullability must match")
    _receipt_reference(previous_id, previous_hash, field="previous_receipt")
    _signature(raw["signature"], session_key, body)
    return Command(
        body=dict(body),
        command_id=_uuid(body["command_id"], "command_id"),
        claim_id=_uuid(body["claim_id"], "claim_id"),
        action=action,
        issue=issue,
        principal=principal,
        session_id=expected_session,
        session_key=session_key,
        at=at,
        lease_seconds=lease_seconds,
        resources=_resources(body["resources"], issue),
        branch=branch,
        pull_request=pull_request,
        previous_receipt_id=previous_id,
        previous_receipt_hash=previous_hash,
        note=note,
        comment_id=comment_id,
        comment_author=comment_author,
    )


def sign_command(body: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    descriptor = key_descriptor(private_key.public_key().public_bytes_raw())
    candidate = dict(body)
    candidate["session_key"] = descriptor
    candidate["session_id"] = session_id_for(descriptor)
    validate_keys = set(candidate)
    if validate_keys != _COMMAND_BODY_KEYS:
        missing = sorted(_COMMAND_BODY_KEYS - validate_keys)
        extra = sorted(validate_keys - _COMMAND_BODY_KEYS)
        raise CoordinationError(f"command body fields mismatch; missing={missing}, extra={extra}")
    signature = private_key.sign(COMMAND_DOMAIN + canonical_json(candidate))
    wrapper = {
        "body": candidate,
        "signature": {
            "alg": "Ed25519",
            "kid": descriptor["kid"],
            "role": "claim-attestation",
            "value": _b64url_encode(signature),
        },
    }
    validate_command(wrapper)
    return wrapper


def validate_registry(registry: Mapping[str, Any]) -> None:
    if not isinstance(registry, Mapping) or set(registry) != {
        "schema",
        "receipt_authors",
        "principals",
    }:
        raise CoordinationError("principal registry is not closed")
    if registry["schema"] != REGISTRY_SCHEMA:
        raise CoordinationError(f"principal registry schema must be {REGISTRY_SCHEMA}")
    authors = registry["receipt_authors"]
    if not isinstance(authors, list) or not authors or any(not isinstance(x, str) or not x for x in authors):
        raise CoordinationError("receipt_authors must be a non-empty string array")
    if authors != sorted(set(authors)):
        raise CoordinationError("receipt_authors must be sorted and duplicate-free")
    principals = registry["principals"]
    if not isinstance(principals, Mapping):
        raise CoordinationError("principals must be an object")
    for principal, entry in principals.items():
        if not isinstance(principal, str) or not _PRINCIPAL.fullmatch(principal):
            raise CoordinationError("registry principal is malformed")
        if not isinstance(entry, Mapping) or set(entry) != {"enabled", "github_logins"}:
            raise CoordinationError(f"registry entry {principal} is not closed")
        logins = entry["github_logins"]
        if (
            not isinstance(entry["enabled"], bool)
            or not isinstance(logins, list)
            or not logins
            or any(not isinstance(login, str) or not login for login in logins)
            or logins != sorted(set(logins))
        ):
            raise CoordinationError(f"registry entry {principal} is malformed")


def authorize_command(command: Command, registry: Mapping[str, Any]) -> None:
    validate_registry(registry)
    entry = registry["principals"].get(command.principal)
    if not isinstance(entry, Mapping) or entry.get("enabled") is not True:
        raise CoordinationError(f"principal {command.principal} is not enabled")
    if command.comment_author not in entry["github_logins"]:
        raise CoordinationError(
            f"GitHub user {command.comment_author!r} cannot onboard session for {command.principal}"
        )


def _receipt_digest(body: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(RECEIPT_DOMAIN + canonical_json(body)).digest()


def build_receipt(body: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(body, Mapping) or set(body) != _RECEIPT_BODY_KEYS:
        raise CoordinationError("receipt body is not closed")
    digest = _receipt_digest(body)
    wrapper = {
        "body": dict(body),
        "receipt_id": "dm:claim-receipt:v0:" + _b64url_encode(digest),
        "receipt_hash": _b64url_encode(digest),
    }
    validate_receipt(wrapper)
    return wrapper


def validate_receipt(
    raw: Mapping[str, Any],
    *,
    comment_id: int | None = None,
    comment_author: str | None = None,
) -> Receipt:
    if not isinstance(raw, Mapping) or set(raw) != _RECEIPT_WRAPPER_KEYS:
        raise CoordinationError("receipt wrapper is not closed")
    body = raw["body"]
    if not isinstance(body, Mapping) or set(body) != _RECEIPT_BODY_KEYS:
        raise CoordinationError("receipt body is not a closed v0 body")
    if body["schema"] != RECEIPT_SCHEMA:
        raise CoordinationError(f"receipt schema must be {RECEIPT_SCHEMA}")
    digest = _receipt_digest(body)
    digest_text = _b64url_encode(digest)
    if raw["receipt_hash"] != digest_text or raw["receipt_id"] != "dm:claim-receipt:v0:" + digest_text:
        raise CoordinationError("receipt ID/hash does not match canonical body")
    decision = body["decision"]
    if decision not in RECEIPT_DECISIONS:
        raise CoordinationError("unsupported receipt decision")
    action = body["action"]
    if action not in COMMAND_ACTIONS | {"expire"}:
        raise CoordinationError("unsupported receipt action")
    issue = _issue(body["issue"])
    principal = body["principal"]
    if not isinstance(principal, str) or not _PRINCIPAL.fullmatch(principal):
        raise CoordinationError("receipt principal is malformed")
    session_id = body["session_id"]
    if not isinstance(session_id, str) or not session_id.startswith("dm:coord-session:v0:"):
        raise CoordinationError("receipt session_id is malformed")
    _b64url_decode(
        session_id.removeprefix("dm:coord-session:v0:"),
        field="receipt.session_id",
        size=32,
    )
    reason = body["reason"]
    if not isinstance(reason, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", reason):
        raise CoordinationError("receipt reason is malformed")
    state = body["state"]
    if state not in ACTIVE_STATES | TERMINAL_STATES:
        raise CoordinationError("unsupported receipt state")
    at = parse_timestamp(body["at"], "receipt.at")
    lease_until = None if body["lease_until"] is None else parse_timestamp(body["lease_until"], "receipt.lease_until")
    if state in ACTIVE_STATES:
        if lease_until is None or lease_until <= at or lease_until - at > dt.timedelta(seconds=MAX_LEASE_SECONDS):
            raise CoordinationError("active receipt lease is invalid")
    elif lease_until is not None:
        raise CoordinationError("terminal receipt must have null lease")
    if decision == "expired" and (action != "expire" or state != "ready" or body["command_id"] is not None):
        raise CoordinationError("expiry receipt shape is invalid")
    if decision != "expired" and body["command_id"] is None:
        raise CoordinationError("command decision requires command_id")
    if body["command_id"] is not None:
        _uuid(body["command_id"], "receipt.command_id")
    previous_id = body["previous_receipt_id"]
    previous_hash = body["previous_receipt_hash"]
    if (previous_id is None) != (previous_hash is None):
        raise CoordinationError("receipt predecessor ID/hash nullability must match")
    _receipt_reference(previous_id, previous_hash, field="receipt.previous_receipt")
    resources = _resources(body["resources"], issue)
    branch = _branch(body["branch"])
    if branch is None:
        raise CoordinationError("receipt requires immutable branch")
    pull_request = body["pull_request"]
    if pull_request is not None and (isinstance(pull_request, bool) or not isinstance(pull_request, int) or pull_request < 1):
        raise CoordinationError("receipt pull_request must be positive or null")
    workflow_sha = body["workflow_sha"]
    if not isinstance(workflow_sha, str) or not _SHA.fullmatch(workflow_sha):
        raise CoordinationError("workflow_sha must be a lowercase 40-hex commit")
    return Receipt(
        body=dict(body),
        receipt_id=raw["receipt_id"],
        receipt_hash=digest_text,
        decision=decision,
        action=action,
        reason=reason,
        command_id=body["command_id"],
        claim_id=_uuid(body["claim_id"], "receipt.claim_id"),
        issue=issue,
        principal=principal,
        session_id=session_id,
        state=state,
        at=at,
        lease_until=lease_until,
        resources=resources,
        branch=branch,
        pull_request=pull_request,
        previous_receipt_id=previous_id,
        previous_receipt_hash=previous_hash,
        workflow_sha=workflow_sha,
        comment_id=comment_id,
        comment_author=comment_author,
    )


def render_block(marker: str, wrapper: Mapping[str, Any], slash_command: str | None = None) -> str:
    prefix = f"/{slash_command}\n\n" if slash_command else ""
    payload = canonical_json(wrapper).decode("ascii")
    return f"{prefix}<!-- {marker}\n{payload}\n-->"


def _parse_one_block(comment: Mapping[str, Any], marker: str, pattern: re.Pattern[str]) -> Mapping[str, Any] | None:
    body = comment.get("body", "")
    if not isinstance(body, str):
        raise CoordinationError("comment body must be text")
    starts = len(re.findall(rf"<!--\s*{re.escape(marker)}\b", body))
    matches = tuple(pattern.finditer(body))
    if starts != len(matches):
        raise CoordinationError(f"comment {comment.get('id', '?')} has unterminated {marker} block")
    if len(matches) > 1:
        raise CoordinationError(f"comment {comment.get('id', '?')} contains multiple {marker} blocks")
    if not matches:
        return None
    if comment.get("created_at") and comment.get("updated_at") and comment["created_at"] != comment["updated_at"]:
        raise CoordinationError(f"comment {comment.get('id', '?')} was edited")
    try:
        parsed = json.loads(matches[0].group("payload"))
    except json.JSONDecodeError as exc:
        raise CoordinationError(f"comment {comment.get('id', '?')} has invalid JSON") from exc
    return parsed


def parse_command_comment(comment: Mapping[str, Any]) -> Command | None:
    raw = _parse_one_block(comment, COMMAND_MARKER, _COMMAND_BLOCK)
    if raw is None:
        return None
    author = comment.get("user", {}).get("login") if isinstance(comment.get("user"), Mapping) else comment.get("author")
    return validate_command(raw, comment_id=comment.get("id"), comment_author=author)


def parse_receipt_comment(comment: Mapping[str, Any], registry: Mapping[str, Any]) -> Receipt | None:
    raw = _parse_one_block(comment, RECEIPT_MARKER, _RECEIPT_BLOCK)
    if raw is None:
        return None
    author = comment.get("user", {}).get("login") if isinstance(comment.get("user"), Mapping) else comment.get("author")
    validate_registry(registry)
    if author not in registry["receipt_authors"]:
        raise CoordinationError(f"receipt comment author {author!r} is not authorized")
    return validate_receipt(raw, comment_id=comment.get("id"), comment_author=author)


def reduce_receipts(receipts: Iterable[Receipt], issue: IssueRef) -> Receipt | None:
    ordered = sorted(receipts, key=lambda item: item.comment_id or 0)
    previous: Receipt | None = None
    seen: set[str] = set()
    for receipt in ordered:
        if receipt.issue != issue:
            raise CoordinationError("receipt belongs to another issue")
        if receipt.receipt_id in seen:
            raise CoordinationError(f"duplicate receipt {receipt.receipt_id}")
        seen.add(receipt.receipt_id)
        expected_id = previous.receipt_id if previous else None
        expected_hash = previous.receipt_hash if previous else None
        if receipt.previous_receipt_id != expected_id or receipt.previous_receipt_hash != expected_hash:
            raise CoordinationError("receipt chain is missing, reordered, or forked")
        if previous and receipt.at < previous.at:
            raise CoordinationError("receipt time regressed")
        previous = receipt
    return previous


def _same_claim(command: Command, current: Receipt) -> str | None:
    if command.claim_id != current.claim_id:
        return "claim_id_mismatch"
    if command.principal != current.principal or command.session_id != current.session_id:
        return "claimant_session_mismatch"
    if command.resources != current.resources or command.branch != current.branch:
        return "claim_scope_changed"
    if (
        command.action == "review"
        and current.pull_request is not None
        and command.pull_request != current.pull_request
    ):
        return "pull_request_changed"
    return None


def _receipt_body(
    *,
    command: Command | None,
    current: Receipt | None,
    issue: IssueRef,
    now: dt.datetime,
    workflow_sha: str,
    decision: str,
    action: str,
    reason: str,
    state: str,
    lease_until: dt.datetime | None,
) -> dict[str, Any]:
    source = current if decision == "rejected" and current is not None else command or current
    if source is None:
        raise CoordinationError("receipt requires command or current state")
    return {
        "schema": RECEIPT_SCHEMA,
        "decision": decision,
        "action": action,
        "reason": reason,
        "command_id": command.command_id if command else None,
        "claim_id": source.claim_id,
        "issue": {"repository": issue.repository, "number": issue.number},
        "principal": source.principal,
        "session_id": source.session_id,
        "state": state,
        "at": format_timestamp(now),
        "lease_until": format_timestamp(lease_until) if lease_until else None,
        "resources": list(source.resources),
        "branch": source.branch,
        "pull_request": (
            command.pull_request
            if command is not None and command.action == "review"
            else current.pull_request
            if current is not None
            else command.pull_request
            if command is not None
            else None
        ),
        "previous_receipt_id": current.receipt_id if current else None,
        "previous_receipt_hash": current.receipt_hash if current else None,
        "workflow_sha": workflow_sha,
    }


def expire_if_due(current: Receipt | None, *, now: dt.datetime, workflow_sha: str) -> dict[str, Any] | None:
    if current is None or current.state not in ACTIVE_STATES or current.lease_until is None or current.lease_until > now:
        return None
    return build_receipt(
        _receipt_body(
            command=None,
            current=current,
            issue=current.issue,
            now=now,
            workflow_sha=workflow_sha,
            decision="expired",
            action="expire",
            reason="lease_expired",
            state="ready",
            lease_until=None,
        )
    )


def decide_command(
    command: Command,
    current: Receipt | None,
    *,
    now: dt.datetime,
    workflow_sha: str,
    issue_ready: bool,
    conflict_reason: str | None = None,
) -> dict[str, Any]:
    if now.tzinfo is None or now.utcoffset() != dt.timedelta(0):
        raise CoordinationError("decision clock must be timezone-aware UTC")
    if abs(now - command.at) > MAX_CLOCK_SKEW:
        reason = "command_clock_skew"
    elif command.issue.resource not in command.resources:
        reason = "missing_issue_resource"
    elif command.previous_receipt_id != (current.receipt_id if current else None) or command.previous_receipt_hash != (current.receipt_hash if current else None):
        reason = "stale_receipt_head"
    elif conflict_reason is not None:
        reason = conflict_reason
    elif command.action == "claim":
        if current and current.state in ACTIVE_STATES and current.lease_until and current.lease_until > now:
            reason = "already_claimed"
        elif not issue_ready:
            reason = "issue_not_ready"
        else:
            reason = "accepted"
    elif current is None or current.state not in ACTIVE_STATES or current.lease_until is None or current.lease_until <= now:
        reason = "no_live_claim"
    else:
        reason = _same_claim(command, current) or "accepted"

    accepted = reason == "accepted"
    if not accepted:
        if current is None:
            state = "ready"
            lease_until = None
        else:
            state = current.state
            lease_until = current.lease_until
        return build_receipt(
            _receipt_body(
                command=command,
                current=current,
                issue=command.issue,
                now=now,
                workflow_sha=workflow_sha,
                decision="rejected",
                action=command.action,
                reason=reason,
                state=state,
                lease_until=lease_until,
            )
        )

    if command.action == "release":
        state = "ready"
        lease_until = None
    elif command.action == "review":
        state = "in_review"
        lease_until = now + dt.timedelta(seconds=command.lease_seconds or 0)
    elif command.action == "heartbeat" and current is not None:
        state = current.state
        lease_until = now + dt.timedelta(seconds=command.lease_seconds or 0)
    else:
        state = "in_progress"
        lease_until = now + dt.timedelta(seconds=command.lease_seconds or 0)
    return build_receipt(
        _receipt_body(
            command=command,
            current=current,
            issue=command.issue,
            now=now,
            workflow_sha=workflow_sha,
            decision="accepted",
            action=command.action,
            reason="accepted",
            state=state,
            lease_until=lease_until,
        )
    )


def audit_resource_overlaps(receipts: Iterable[Receipt], *, now: dt.datetime) -> tuple[Finding, ...]:
    live = [receipt for receipt in receipts if receipt.is_live(now)]
    findings: list[Finding] = []
    for index, left in enumerate(live):
        for right in live[index + 1 :]:
            overlap = sorted(set(left.resources).intersection(right.resources))
            if overlap and left.claim_id != right.claim_id:
                findings.append(
                    Finding(
                        "overlapping_claims",
                        f"{left.claim_id} and {right.claim_id} overlap on {', '.join(overlap)}",
                    )
                )
    return tuple(findings)
