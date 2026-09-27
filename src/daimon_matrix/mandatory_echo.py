"""Runtime-only V2 echo journal, NOT an activated native egress integration.

The caller owns the native SQLite connection, path safety, global schema catalog,
transaction admission and custody. No database/key creation or model signer API.
See docs/mandatory-telegram-visibility.md for mandatory integration obligations.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext, suppress
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from .telegram_mirror import classify_plain_response, plain_request, render_plain_parts

SCHEMA = "daimon-echo-proof/v2"
MAX_RECORDS = 4096
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ATTEMPTS = 4
# Exact owned subset; parent MUST add these to its complete native store catalog.
TABLE_SQL = {
    "echo_v2_catalog": (
        "CREATE TABLE echo_v2_catalog "
        "(catalog_id TEXT PRIMARY KEY, authentication TEXT NOT NULL)"
    ),
    "echo_v2_obligations": (
        "CREATE TABLE echo_v2_obligations "
        "(operation_id TEXT PRIMARY KEY, record TEXT NOT NULL)"
    ),
}


class EchoError(ValueError):
    """Stable sanitized local error; no request, token or response content."""


@dataclass(frozen=True)
class RetryDecision:
    """Verified owner command, produced ONLY by installed runtime verifier."""

    authorization_id: str
    actor: str
    operation_id: str
    binding_digest: str
    attempt_id: str
    approved_at_ms: int
    expires_at_ms: int
    risk: str


class EchoTransport(Protocol):
    def send(self, request: dict[str, Any]) -> bytes: ...


def _json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(_json(value))


def _text(value: Any, limit: int = 256) -> None:
    if type(value) is not str or not 0 < len(value) <= limit:
        raise ValueError
    value.encode("utf-8")


def _digest_field(value: Any) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError


def _fields(value: Any, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError


def validate_policy(policy: dict[str, Any]) -> None:
    """Closed public policy shape; signature/enrollment authority is external."""
    try:
        _fields(
            policy,
            {
                "schema",
                "generation",
                "origin",
                "bot_id",
                "chat_id",
                "topic_id",
                "representation",
                "acceptance_digest",
                "proof_key_id",
            },
        )
        if (
            policy["schema"] != "daimon-visibility-policy/v2"
            or policy["representation"] != "plain-json/v2"
        ):
            raise ValueError
        if (
            type(policy["generation"]) is not int
            or not 0 < policy["generation"] < 2**52
        ):
            raise ValueError
        if type(policy["bot_id"]) is not int or not 0 < policy["bot_id"] < 2**52:
            raise ValueError
        _text(policy["origin"], 128)
        _text(policy["proof_key_id"], 128)
        _digest_field(policy["acceptance_digest"])
        plain_request(
            "validate", chat_id=policy["chat_id"], topic_id=policy["topic_id"]
        )
    except Exception:
        raise EchoError("echo_policy_invalid") from None


def validate_projection(projection: dict[str, Any]) -> None:
    """Safe typed registry. No generic control/echo/secret or fanout escape hatch."""
    try:
        _fields(
            projection,
            {
                "event_id",
                "event_digest",
                "sender",
                "recipients",
                "thread_id",
                "reply_to",
                "kind",
                "content",
            },
        )
        for field in ("event_id", "sender", "thread_id"):
            _text(projection[field])
        _digest_field(projection["event_digest"])
        recipients = projection["recipients"]
        if type(recipients) is not list or len(recipients) != 1:
            raise ValueError
        _text(recipients[0])
        kind, content, reply = (
            projection["kind"],
            projection["content"],
            projection["reply_to"],
        )
        if kind == "message" and reply is not None:
            raise ValueError
        if kind in ("reply", "semantic-receipt") and reply is None:
            raise ValueError
        if reply is not None:
            _fields(reply, {"event_id", "event_digest"})
            _text(reply["event_id"])
            _digest_field(reply["event_digest"])
        if kind in ("message", "reply"):
            _fields(content, {"text"})
            _text(content["text"], 65536)
            if len(content["text"].encode()) > 65536:
                raise ValueError
        elif kind == "semantic-receipt":
            _fields(content, {"outcome"})
            if content["outcome"] not in (
                "delivered",
                "failed:transport",
                "refused:policy",
                "expired",
                "resolved:unroutable",
            ):
                raise ValueError
        elif kind == "transport-result":
            _fields(content, {"stage", "outcome"})
            if content["stage"] not in ("evidence", "message") or content[
                "outcome"
            ] not in ("accepted", "refused"):
                raise ValueError
        elif kind == "authorization-control":
            _fields(content, {"stage"})
            if content["stage"] not in (
                "evidence-before-message",
                "scope",
                "sync",
                "converse",
                "transport-response",
                "semantic-receipt",
            ):
                raise ValueError
        else:
            raise ValueError
        render_plain_parts(
            json.dumps(projection, ensure_ascii=False, sort_keys=True, indent=2)
        )
    except Exception:
        raise EchoError("echo_projection_invalid") from None


def _millis(value: Any) -> None:
    if type(value) is not int or not 0 <= value < 2**52:
        raise ValueError


def _part_result(part: dict[str, Any], policy: dict[str, Any]) -> tuple[str, int]:
    if not part["attempts"]:
        return "queued", 0
    attempt = part["attempts"][-1]
    if attempt["response"] is None:
        return "ambiguous", 0
    result, delay = classify_plain_response(
        attempt["response"].encode(),
        plain_request(
            part["text"], chat_id=policy["chat_id"], topic_id=policy["topic_id"]
        ),
        bot_id=policy["bot_id"],
    )
    return result, attempt["response_at_ms"] + delay * 1000


def _validate_retry(
    approval: dict[str, Any], binding: dict[str, Any], previous_id: str, at_ms: int
) -> None:
    _fields(approval, {"decision", "evidence"})
    decision = approval["decision"]
    _fields(decision, set(RetryDecision.__dataclass_fields__))
    ident = uuid.UUID(decision["authorization_id"])
    if str(ident) != decision["authorization_id"] or ident.version != 4:
        raise ValueError
    _text(decision["actor"], 128)
    _millis(decision["approved_at_ms"])
    _millis(decision["expires_at_ms"])
    if (
        decision["operation_id"] != binding["operation_id"]
        or decision["binding_digest"] != _hash(binding)
        or decision["attempt_id"] != previous_id
        or decision["risk"] != "duplicate-platform-post-accepted"
        or not decision["approved_at_ms"] <= at_ms < decision["expires_at_ms"]
        or decision["expires_at_ms"] - decision["approved_at_ms"] > 60000
    ):
        raise ValueError
    evidence = base64.b64decode(approval["evidence"], validate=True)
    if (
        not 0 < len(evidence) <= 8192
        or base64.b64encode(evidence).decode() != approval["evidence"]
    ):
        raise ValueError


def validate_proof_shape(record: dict[str, Any]) -> None:
    """Structural/transcript validation ONLY, never runtime authentication."""
    try:
        _fields(
            record,
            {
                "schema",
                "catalog_id",
                "revision",
                "binding",
                "binding_digest",
                "parts",
                "authentication",
            },
        )
        if record["schema"] != SCHEMA:
            raise ValueError
        _text(record["catalog_id"], 128)
        _digest_field(record["authentication"])
        _digest_field(record["binding_digest"])
        binding = record["binding"]
        _fields(binding, {"operation_id", "projection", "policy"})
        _text(binding["operation_id"], 128)
        validate_projection(binding["projection"])
        validate_policy(binding["policy"])
        if _hash(binding) != record["binding_digest"]:
            raise ValueError
        texts = render_plain_parts(
            json.dumps(
                binding["projection"], ensure_ascii=False, sort_keys=True, indent=2
            )
        )
        parts = record["parts"]
        if type(parts) is not list or len(parts) != len(texts):
            raise ValueError
        revision, attempt_ids = 0, set()
        decision_ids: set[str] = set()
        unfinished = False
        for part, text in zip(parts, texts, strict=True):
            _fields(part, {"text", "attempts"})
            if part["text"] != text:
                raise ValueError
            attempts = part["attempts"]
            if type(attempts) is not list or len(attempts) > MAX_ATTEMPTS:
                raise ValueError
            if unfinished and attempts:
                raise ValueError
            request = plain_request(
                text,
                chat_id=binding["policy"]["chat_id"],
                topic_id=binding["policy"]["topic_id"],
            )
            previous = None
            for attempt in attempts:
                _fields(
                    attempt,
                    {
                        "attempt_id",
                        "request_digest",
                        "response",
                        "at_ms",
                        "response_at_ms",
                        "retry_authorization",
                    },
                )
                _millis(attempt["at_ms"])
                if previous is not None:
                    result, earliest = _part_result(
                        {"text": text, "attempts": [previous]}, binding["policy"]
                    )
                    if result == "ambiguous":
                        _validate_retry(
                            attempt["retry_authorization"],
                            binding,
                            previous["attempt_id"],
                            attempt["at_ms"],
                        )
                        decision_id = attempt["retry_authorization"]["decision"][
                            "authorization_id"
                        ]
                        if decision_id in decision_ids:
                            raise ValueError
                        decision_ids.add(decision_id)
                    elif (
                        result != "rejected"
                        or attempt["at_ms"] < earliest
                        or attempt["retry_authorization"] is not None
                    ):
                        raise ValueError
                elif attempt["retry_authorization"] is not None:
                    raise ValueError
                ident = attempt["attempt_id"]
                parsed = uuid.UUID(ident)
                if str(parsed) != ident or parsed.version != 4 or ident in attempt_ids:
                    raise ValueError
                attempt_ids.add(ident)
                if attempt["request_digest"] != _hash(request):
                    raise ValueError
                revision += 1
                if attempt["response"] is not None:
                    _millis(attempt["response_at_ms"])
                    if attempt["response_at_ms"] < attempt["at_ms"]:
                        raise ValueError
                    classify_plain_response(
                        attempt["response"].encode(),
                        request,
                        bot_id=binding["policy"]["bot_id"],
                    )
                    revision += 1
                elif attempt["response_at_ms"] is not None:
                    raise ValueError
                previous = attempt
            unfinished = _part_result(part, binding["policy"])[0] != "confirmed"
        if type(record["revision"]) is not int or record["revision"] != revision:
            raise ValueError
    except Exception:
        raise EchoError("echo_proof_invalid") from None


class EchoJournal:
    """Owner-local capability: never expose instances/keys to model-facing tools.

    initialize/admit require an existing parent BEGIN IMMEDIATE and NEVER commit.
    Reopen does no DDL. Worker transitions use short independent transactions on
    the same native store (no transaction is held during HTTP).
    """

    def __init__(
        self, db: sqlite3.Connection, *, catalog_id: str, authentication_key: bytes
    ) -> None:
        if type(authentication_key) is not bytes or len(authentication_key) != 32:
            raise EchoError("echo_key_invalid")
        if type(catalog_id) is not str or not 0 < len(catalog_id) <= 128:
            raise EchoError("echo_catalog_invalid")
        self.db = db
        self._catalog_id = catalog_id
        self.__key = authentication_key
        self._check_catalog()

    @classmethod
    def initialize(
        cls, db: sqlite3.Connection, *, catalog_id: str, authentication_key: bytes
    ) -> None:
        if not db.in_transaction:
            raise EchoError("echo_transaction_required")
        if type(authentication_key) is not bytes or len(authentication_key) != 32:
            raise EchoError("echo_key_invalid")
        if type(catalog_id) is not str or not 0 < len(catalog_id) <= 128:
            raise EchoError("echo_catalog_invalid")
        try:
            for sql in TABLE_SQL.values():
                db.execute(sql)
            tag = hmac.new(
                authentication_key,
                b"daimon-echo-catalog/v2\0" + _json([catalog_id, TABLE_SQL]).encode(),
                hashlib.sha256,
            ).hexdigest()
            db.execute("INSERT INTO echo_v2_catalog VALUES (?,?)", (catalog_id, tag))
        except Exception:
            raise EchoError("echo_initialization_failed") from None

    def _check_catalog(self) -> None:
        try:
            if self.db.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise ValueError
            if self.db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise ValueError
            rows = [
                tuple(row)
                for row in self.db.execute(
                    "SELECT name,type,sql FROM sqlite_master WHERE tbl_name IN "
                    "('echo_v2_catalog','echo_v2_obligations') OR name GLOB 'echo_v2_*'"
                ).fetchall()
            ]
            expected_schema: set[tuple[str, str, str | None]] = {
                (name, "table", sql) for name, sql in TABLE_SQL.items()
            }
            expected_schema.update(
                (f"sqlite_autoindex_{name}_1", "index", None) for name in TABLE_SQL
            )
            if set(rows) != expected_schema:
                raise ValueError
            rows = self.db.execute(
                "SELECT catalog_id,authentication FROM echo_v2_catalog"
            ).fetchall()
            expected = hmac.new(
                self.__key,
                b"daimon-echo-catalog/v2\0"
                + _json([self._catalog_id, TABLE_SQL]).encode(),
                hashlib.sha256,
            ).hexdigest()
            if (
                len(rows) != 1
                or rows[0][0] != self._catalog_id
                or not hmac.compare_digest(rows[0][1], expected)
            ):
                raise ValueError
        except Exception:
            raise EchoError("echo_catalog_invalid") from None

    def _authenticate(self, record: dict[str, Any]) -> str:
        value = {k: v for k, v in record.items() if k != "authentication"}
        return hmac.new(
            self.__key,
            b"daimon-echo-proof/v2\0" + _json(value).encode(),
            hashlib.sha256,
        ).hexdigest()

    def admit(
        self, operation_id: str, projection: dict[str, Any], policy: dict[str, Any]
    ) -> str:
        """Trusted producer; SAME parent transaction as logical admission."""
        try:
            return self._admit(operation_id, projection, policy)
        except EchoError:
            raise
        except Exception:
            raise EchoError("echo_storage_unavailable") from None

    def _admit(
        self, operation_id: str, projection: dict[str, Any], policy: dict[str, Any]
    ) -> str:
        self._check_catalog()
        if not self.db.in_transaction:
            raise EchoError("echo_transaction_required")
        validate_projection(projection)
        validate_policy(policy)
        try:
            _text(operation_id, 128)
        except Exception:
            raise EchoError("echo_operation_invalid") from None
        binding = {
            "operation_id": operation_id,
            "policy": _copy(policy),
            "projection": _copy(projection),
        }
        digest = _hash(binding)
        texts = render_plain_parts(
            json.dumps(projection, ensure_ascii=False, sort_keys=True, indent=2)
        )
        if self.db.execute(
            "SELECT 1 FROM echo_v2_obligations WHERE operation_id=?", (operation_id,)
        ).fetchone():
            self._load(operation_id, digest)
            return digest
        if (
            self.db.execute("SELECT count(*) FROM echo_v2_obligations").fetchone()[0]
            >= MAX_RECORDS
        ):
            raise EchoError("echo_capacity")
        record = {
            "schema": SCHEMA,
            "catalog_id": self._catalog_id,
            "revision": 0,
            "binding": binding,
            "binding_digest": digest,
            "parts": [{"text": text, "attempts": []} for text in texts],
        }
        self._write(record, insert=True)
        return digest

    def _write(self, record: dict[str, Any], *, insert: bool = False) -> None:
        if not self.db.in_transaction:
            raise EchoError("echo_transaction_required")
        record["authentication"] = self._authenticate(record)
        # Never persist a candidate that our authenticated loader would reject.
        validate_proof_shape(record)
        raw = _json(record)
        size = len(raw.encode())
        if size > MAX_RECORD_BYTES:
            raise EchoError("echo_capacity")
        op = record["binding"]["operation_id"]
        total = self.db.execute(
            "SELECT coalesce(sum(length(CAST(record AS BLOB))),0) "
            "FROM echo_v2_obligations WHERE operation_id != ?",
            (op,),
        ).fetchone()[0]
        if total + size > MAX_TOTAL_BYTES:
            raise EchoError("echo_capacity")
        if insert:
            self.db.execute("INSERT INTO echo_v2_obligations VALUES (?,?)", (op, raw))
        else:
            self.db.execute(
                "UPDATE echo_v2_obligations SET record=? WHERE operation_id=?",
                (raw, op),
            )

    def _load(self, operation_id: str, expected_binding_digest: str) -> dict[str, Any]:
        self._check_catalog()
        try:
            row = self.db.execute(
                "SELECT record FROM echo_v2_obligations WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise EchoError("echo_state_missing")
            if type(row[0]) is not str or len(row[0].encode()) > MAX_RECORD_BYTES:
                raise ValueError
            record = json.loads(row[0])
            if row[0] != _json(record):
                raise ValueError
            if (
                not hmac.compare_digest(
                    record["authentication"], self._authenticate(record)
                )
                or record["schema"] != SCHEMA
                or record["catalog_id"] != self._catalog_id
                or record["binding"]["operation_id"] != operation_id
                or record["binding_digest"] != expected_binding_digest
                or _hash(record["binding"]) != expected_binding_digest
            ):
                raise ValueError
            validate_proof_shape(record)
            return dict(record)
        except EchoError:
            raise
        except Exception:
            raise EchoError("echo_state_invalid") from None

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        try:
            active = self.db.in_transaction
        except sqlite3.Error:
            raise EchoError("echo_storage_unavailable") from None
        if active:
            raise EchoError("echo_transaction_active")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            yield
            self.db.commit()
        except BaseException as exc:
            with suppress(sqlite3.Error):
                self.db.rollback()
            if isinstance(exc, Exception) and not isinstance(exc, EchoError):
                raise EchoError("echo_storage_unavailable") from None
            raise


def _status(record: dict[str, Any]) -> dict[str, Any]:
    outcomes = [
        _part_result(p, record["binding"]["policy"])[0] for p in record["parts"]
    ]
    completed = outcomes.count("confirmed")
    state = (
        "confirmed"
        if completed == len(outcomes)
        else "ambiguous"
        if "ambiguous" in outcomes
        else "queued"
    )
    return {
        "state": state,
        "confirmed_parts": completed,
        "part_count": len(outcomes),
        "binding_digest": record["binding_digest"],
    }


class MandatoryEcho:
    """Bounded runtime worker + exact-binding gate. Never sends native traffic.

    resolve authenticates the retained immutable logical event. authorize checks
    current runtime fence, native authority AND disclosed fixed-audience consent.
    Both are installed runtime capabilities, not caller flags or model tools.
    """

    def __init__(
        self,
        journal: EchoJournal,
        *,
        transport: EchoTransport | None,
        resolve: Callable[[str], dict[str, Any]],
        authorize: Callable[[dict[str, Any]], bool],
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
        verify_retry: Callable[[bytes, dict[str, Any], str], RetryDecision | None]
        | None = None,
        execution_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> None:
        self._journal, self._transport = journal, transport
        self._resolve, self._authorize = resolve, authorize
        self._clock = clock
        self._verify_retry, self._execution_guard = verify_retry, execution_guard

    def _current(self, record: dict[str, Any]) -> None:
        try:
            binding = record["binding"]
            if (
                self._resolve(binding["operation_id"]) != binding["projection"]
                or self._authorize(_copy(binding)) is not True
            ):
                raise ValueError
        except Exception:
            raise EchoError("echo_authorization_blocked") from None

    def inspect(
        self, operation_id: str, expected_binding_digest: str
    ) -> dict[str, Any]:
        record = self._journal._load(operation_id, expected_binding_digest)
        self._current(record)
        return _status(record)

    def ambiguity(
        self, operation_id: str, expected_binding_digest: str
    ) -> dict[str, str]:
        """Return only the exact identifiers needed for an owner retry command."""

        record = self._journal._load(operation_id, expected_binding_digest)
        self._current(record)
        if _status(record)["state"] != "ambiguous":
            raise EchoError("echo_retry_not_ambiguous")
        policy = record["binding"]["policy"]
        part = next(
            item
            for item in record["parts"]
            if _part_result(item, policy)[0] != "confirmed"
        )
        attempt = part["attempts"][-1]
        return {
            "echo_operation_id": record["binding"]["operation_id"],
            "echo_binding_digest": record["binding_digest"],
            "latest_attempt_id": attempt["attempt_id"],
        }

    def require_confirmed(
        self, operation_id: str, expected_binding_digest: str
    ) -> dict[str, Any]:
        """Revalidate evidence/current authority; not a reusable bearer grant."""
        record = self._journal._load(operation_id, expected_binding_digest)
        self._current(record)
        if _status(record)["state"] != "confirmed":
            raise EchoError("echo_not_confirmed")
        return record

    def _checkpoint(self, point: str) -> None:
        """Private fault-injection seam; no runtime configuration or model API."""

    def advance(
        self, operation_id: str, expected_binding_digest: str
    ) -> dict[str, Any]:
        """One part; retry only demonstrably rejected attempts after backoff."""
        return self._guarded_advance(operation_id, expected_binding_digest, None)

    def retry_ambiguous(
        self, operation_id: str, expected_binding_digest: str, authorization: bytes
    ) -> dict[str, Any]:
        """OWNER/runtime-only verified duplicate-risk recovery, never a model API."""
        if self._verify_retry is None or self._execution_guard is None:
            raise EchoError("echo_recovery_unavailable")
        if type(authorization) is not bytes or not 0 < len(authorization) <= 8192:
            raise EchoError("echo_retry_unauthorized")
        return self._guarded_advance(
            operation_id, expected_binding_digest, authorization
        )

    def _guarded_advance(
        self,
        operation_id: str,
        expected_binding_digest: str,
        authorization: bytes | None,
    ) -> dict[str, Any]:
        try:
            with self._execution_guard() if self._execution_guard else nullcontext():
                return self._advance(
                    operation_id, expected_binding_digest, authorization
                )
        except EchoError:
            raise
        except Exception:
            raise EchoError("echo_execution_unavailable") from None

    def _advance(
        self,
        operation_id: str,
        expected_binding_digest: str,
        authorization: bytes | None,
    ) -> dict[str, Any]:
        journal = self._journal
        with journal._transaction():
            record = journal._load(operation_id, expected_binding_digest)
            self._current(record)
            state = _status(record)
            evidence = (
                base64.b64encode(authorization).decode()
                if authorization is not None
                else None
            )
            if evidence is not None and any(
                a["retry_authorization"] is not None
                and a["retry_authorization"]["evidence"] == evidence
                for p in record["parts"]
                for a in p["attempts"]
            ):
                return state  # Lost-return retry of an already admitted decision.
            if state["state"] == "confirmed" or self._transport is None:
                return state
            if state["state"] == "ambiguous" and authorization is None:
                return state
            if state["state"] != "ambiguous" and authorization is not None:
                raise EchoError("echo_retry_not_ambiguous")
            policy = record["binding"]["policy"]
            index = next(
                i
                for i, p in enumerate(record["parts"])
                if _part_result(p, policy)[0] != "confirmed"
            )
            part = record["parts"][index]
            now = self._clock()
            _millis(now)
            if len(part["attempts"]) >= MAX_ATTEMPTS:
                raise EchoError("echo_attempt_limit")
            if now < _part_result(part, policy)[1]:
                return state
            approval = None
            if authorization is not None:
                try:
                    if self._verify_retry is None:
                        raise ValueError
                    previous_id = part["attempts"][-1]["attempt_id"]
                    decision = self._verify_retry(
                        authorization, _copy(record["binding"]), previous_id
                    )
                    if type(decision) is not RetryDecision:
                        raise ValueError
                    approval = {"decision": asdict(decision), "evidence": evidence}
                    observed = self._clock()
                    _millis(observed)
                    if observed < now or observed < part["attempts"][-1]["at_ms"]:
                        raise ValueError
                    now = observed
                    _validate_retry(approval, record["binding"], previous_id, now)
                except Exception:
                    raise EchoError("echo_retry_unauthorized") from None
            request = plain_request(
                part["text"], chat_id=policy["chat_id"], topic_id=policy["topic_id"]
            )
            attempt: dict[str, Any] = {
                "attempt_id": str(uuid.uuid4()),
                "request_digest": _hash(request),
                "response": None,
                "at_ms": now,
                "response_at_ms": None,
                "retry_authorization": approval,
            }
            part["attempts"].append(attempt)
            record["revision"] += 1
            journal._write(record)
        self._checkpoint("intent_committed")
        self._current(record)
        try:
            raw = self._transport.send(_copy(request))
            classify_plain_response(raw, request, bot_id=policy["bot_id"])
        except Exception:
            return _status(record)
        self._checkpoint("response_verified")
        with journal._transaction():
            latest = journal._load(operation_id, expected_binding_digest)
            if latest != record:
                raise EchoError("echo_state_conflict")
            observed = self._clock()
            _millis(observed)
            if observed < attempt["at_ms"]:
                raise EchoError("echo_clock_invalid")
            latest["parts"][index]["attempts"][-1].update(
                response=raw.decode("utf-8"), response_at_ms=observed
            )
            latest["revision"] += 1
            journal._write(latest)
        self._checkpoint("response_committed")
        return self.inspect(operation_id, expected_binding_digest)
