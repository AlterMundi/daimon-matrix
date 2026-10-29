"""Private persistence for authenticated sparse foreign evidence, not /we history."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from typing import Any

from .canonical import b64url, canonical_bytes, unb64url
from .mandatory_echo import read_diagnostic, write_diagnostic
from .native_egress import (
    MandatoryEgressController,
    NativeEgressError,
    OperationBinding,
)
from .relationship_store import _prepare_path


class MessagingInboxError(ValueError):
    """Foreign evidence conflicts or local persistence is unsafe."""


class TribeControlCapacityError(ValueError):
    """Temporary control saturation; no readable intake was committed."""


class TribeRecordStore:
    """Owned frozen send plans and received group messages, not foreign ledgers.

    The application supplies the existing operator-binding signer/verifier. The
    low-level primitive may use ownership plus canonical digests in fixtures;
    deployed applications must supply both binding callbacks.
    """

    def __init__(
        self,
        path: Path,
        *,
        sign: Callable[[Any], Any] | None = None,
        verify: Callable[[Any, Any], None] | None = None,
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
        cache_reader_bindings: bool = False,
    ) -> None:
        if (sign is None) != (verify is None):
            raise ValueError("tribe_record_binding_required")
        self.path = path.absolute()
        self.sign, self.verify = sign, verify
        self.clock = clock
        self.cache_reader_bindings = cache_reader_bindings
        self.egress: MandatoryEgressController | None = None
        self.catalog_id: str | None = None
        with self._database() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS tribe_records ("
                "kind TEXT NOT NULL, record_id TEXT NOT NULL, "
                "request_hash TEXT NOT NULL, document BLOB NOT NULL, "
                "binding BLOB NOT NULL, document_hash TEXT NOT NULL, "
                "recorded_at_ms INTEGER NOT NULL, "
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                "UNIQUE(kind, record_id))"
            )

    @contextmanager
    def _database(
        self, *, timeout: float = 5.0, deadline_ns: int | None = None
    ) -> Iterator[sqlite3.Connection]:
        guard = (
            nullcontext()
            if self.egress is None
            else self.egress.local_storage(deadline_ns=deadline_ns)
        )
        with guard as inherited:
            _prepare_path(self.path)
            # A bounded attempt must not add SQLite's per-statement busy wait.
            with closing(
                sqlite3.connect(
                    self.path,
                    isolation_level=None,
                    timeout=timeout if inherited is None and deadline_ns is None else 0,
                )
            ) as database:
                database.row_factory = sqlite3.Row
                database.execute("PRAGMA journal_mode=DELETE")
                database.execute("PRAGMA synchronous=FULL")
                yield database

    def _checked(
        self,
        row: sqlite3.Row | dict[str, Any],
        *,
        reader_bindings: tuple[set[bytes], set[bytes]] | None = None,
    ) -> dict[str, Any]:
        raw = bytes(row["document"])
        value = json.loads(raw)
        if (
            canonical_bytes(value) != raw
            or hashlib.sha256(raw).hexdigest() != row["document_hash"]
        ):
            raise ValueError("tribe_record_corrupt")
        if self.verify is not None:
            signed = {
                "kind": row["kind"],
                "record_id": row["record_id"],
                "request_hash": row["request_hash"],
                "recorded_at_ms": row["recorded_at_ms"],
                "document": value,
            }
            if reader_bindings is None:
                self.verify(signed, json.loads(bytes(row["binding"])))
            else:
                fingerprint = hashlib.sha256(
                    canonical_bytes(
                        {key: item for key, item in signed.items() if key != "document"}
                    )
                    + b"\0" + raw + b"\0" + bytes(row["binding"])
                ).digest()
                # The maintained verifier checks this live clock predicate too.
                # A clock rollback must invalidate a previously warm attestation.
                instant = signed["recorded_at_ms"]
                if (
                    fingerprint not in reader_bindings[0]
                    or type(instant) is not int
                    or not 0 <= instant <= self.clock()
                ):
                    self.verify(signed, json.loads(bytes(row["binding"])))
                reader_bindings[1].add(fingerprint)
        return dict(value)

    def reserve(
        self,
        kind: str,
        record_id: str,
        request: Any,
        factory: Callable[[], dict[str, Any]],
        *,
        deadline_ns: int | None = None,
    ) -> dict[str, Any]:
        if kind not in {
            "send",
            "inbox",
            "receipt",
            "native",
            "transport",
            "request",
            "result",
            "transport-result",
            "intake-admission",
            "receipt-obligation",
            "intake-ack",
            "receipt-terminal",
            "control-proof",
            "control-terminal",
            "recovery",
            "recovery-selection",
            "recovery-intent",
        }:
            raise ValueError("tribe_record_kind_invalid")
        if str(uuid.UUID(record_id)) != record_id:
            raise ValueError("tribe_record_id_invalid")
        request_hash = hashlib.sha256(canonical_bytes(request)).hexdigest()
        with self._database(deadline_ns=deadline_ns) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                result = self._reserve_in_transaction(
                    database, kind, record_id, request_hash, factory
                )
                database.commit()
                return result
            except BaseException:
                database.rollback()
                raise

    def _reserve_in_transaction(
        self,
        database: sqlite3.Connection,
        kind: str,
        record_id: str,
        request_hash: str,
        factory: Callable[[], dict[str, Any]],
    ) -> dict[str, Any]:
        row = database.execute(
            "SELECT * FROM tribe_records WHERE kind=? AND record_id=?",
            (kind, record_id),
        ).fetchone()
        if row is not None:
            if row["request_hash"] != request_hash:
                raise ValueError("tribe_record_request_conflict")
            result = self._checked(row)
        else:
            result = factory()
            raw = canonical_bytes(result)
            recorded_at_ms = self.clock()
            binding = (
                None
                if self.sign is None
                else self.sign(
                    {
                        "kind": kind,
                        "record_id": record_id,
                        "request_hash": request_hash,
                        "recorded_at_ms": recorded_at_ms,
                        "document": result,
                    }
                )
            )
            database.execute(
                "INSERT INTO tribe_records(kind,record_id,request_hash,"
                "document,binding,document_hash,recorded_at_ms) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    kind,
                    record_id,
                    request_hash,
                    raw,
                    canonical_bytes(binding),
                    hashlib.sha256(raw).hexdigest(),
                    recorded_at_ms,
                ),
            )
        return result

    def received(self, message: Any, resolution: Any) -> dict[str, Any]:
        # Identity is the exact signed logical message/resolution, not a renewed
        # carrier's random ciphertext, so retries do not create another inbox row.
        document = {"message": message, "resolution": resolution}
        return self.reserve("inbox", message["event_id"], document, lambda: document)

    def _reader_head(
        self,
        database: sqlite3.Connection,
        channel_id: str,
        *,
        deadline_ns: int | None = None,
    ) -> dict[str, Any] | None:
        # SQL sequence is not signed. Authenticate the revision/predecessor
        # chain, including tombstones; never search for an older matching select.
        # Only immutable, historical reader attestations may reuse signature
        # checks. Every signed field and exact binding byte participates; raw
        # canonical hashes and the complete revision chain are always checked.
        # This cache never authorizes a current reader or bypasses its live fence.
        # Arbitrary injected verifiers may have additional mutable predicates;
        # only the maintained application verifier opts into historical reuse.
        cache_enabled = getattr(self, "cache_reader_bindings", False)
        known: set[bytes] = (
            getattr(self, "_reader_verified_bindings", set())
            if getattr(self, "_reader_verifier", None) is self.verify
            else set()
        )
        checked: set[bytes] = set()
        documents = []
        for row in database.execute(
            "SELECT * FROM tribe_records WHERE kind='reader-control'"
        ):
            self._reader_budget(deadline_ns)
            document = self._checked(
                row, reader_bindings=(known, checked) if cache_enabled else None
            )
            if (
                set(document)
                != {
                    "schema",
                    "channel_id",
                    "revision",
                    "predecessor_sha256",
                    "action",
                    "binding_sha256",
                    "boot",
                    "command",
                    "request_sha256",
                    "roster_sha256",
                }
                or document["schema"]
                not in {
                    "dm.receiving.reader-control-record/v1",
                    "dm.receiving.reader-control-record/v2",
                }
                or document["action"] not in {"control", "rebound", "invalidate"}
            ):
                raise ValueError("reader_journal_record_invalid")
            if (
                document["schema"] == "dm.receiving.reader-control-record/v1"
                and document["command"].get("schema")
                == "dm.runtime.reader-selection/v2"
            ):
                raise ValueError("reader_journal_record_invalid")
            if document.get("channel_id") == channel_id:
                # _checked has already proved canonical raw bytes and their hash.
                # Reuse that exact hash instead of serializing the same boot again.
                documents.append((document, row["document_hash"]))
        documents.sort(key=lambda item: item[0]["revision"])
        previous = None
        previous_hash = None
        for revision, (document, document_hash) in enumerate(documents, 1):
            if (
                type(document["revision"]) is not int
                or document["revision"] != revision
                or document["predecessor_sha256"] != previous_hash
            ):
                raise ValueError("reader_journal_chain_invalid")
            previous = document
            previous_hash = document_hash
        # Publish only after the full current chain is accepted. Removed rows
        # leave no cache entries, and a changed verifier starts cold.
        self._reader_verifier = self.verify
        self._reader_verified_bindings = checked
        return previous

    @staticmethod
    def _reader_budget(deadline_ns: int | None) -> None:
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise ValueError("reader_journal_deadline_expired")

    def reader_control_head(
        self, channel_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any] | None:
        self._reader_budget(deadline_ns)
        with self._database(timeout=0, deadline_ns=deadline_ns) as database:
            return self._reader_head(database, channel_id, deadline_ns=deadline_ns)

    def append_reader_control(
        self,
        channel_id: str,
        previous: dict[str, Any] | None,
        document: dict[str, Any],
        *,
        deadline_ns: int | None = None,
    ) -> dict[str, Any]:
        """Durable authenticated local intent; no inbox or visibility operation."""
        self._reader_budget(deadline_ns)
        with self._database(timeout=0, deadline_ns=deadline_ns) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                if (
                    self._reader_head(database, channel_id, deadline_ns=deadline_ns)
                    != previous
                ):
                    raise ValueError("reader_journal_head_conflict")
                typed = (
                    previous is not None
                    and previous["schema"] == "dm.receiving.reader-control-record/v2"
                ) or document["command"].get(
                    "schema"
                ) == "dm.runtime.reader-selection/v2"
                value = {
                    **document,
                    "schema": (
                        "dm.receiving.reader-control-record/v2"
                        if typed
                        else "dm.receiving.reader-control-record/v1"
                    ),
                    "channel_id": channel_id,
                    "revision": 1 if previous is None else previous["revision"] + 1,
                    "predecessor_sha256": None
                    if previous is None
                    else hashlib.sha256(canonical_bytes(previous)).hexdigest(),
                }
                fingerprint = hashlib.sha256(canonical_bytes(value)).hexdigest()
                record_id = str(
                    uuid.uuid5(uuid.NAMESPACE_URL, "dm.reader-control:" + fingerprint)
                )
                result = self._reserve_in_transaction(
                    database, "reader-control", record_id, fingerprint, lambda: value
                )
                self._reader_budget(deadline_ns)
                database.commit()
                return result
            except BaseException:
                database.rollback()
                raise

    def _pending_capacity(self, database: sqlite3.Connection) -> dict[str, int]:
        """Credit requires a verified signed completion bound to its source hash.

        Source frames are hashed but not decoded into Python objects to count
        them. Small completions use the existing operator binding as authority.
        Missing, corrupted or unrelated completion cannot release capacity.
        """
        capacity = {
            "message-ack": 0,
            "control-ack": 0,
            "receipt-obligation": 0,
            "control-proof": 0,
            "message-bytes": 0,
            "control-bytes": 0,
        }
        for kind, completed, digest_field in (
            ("intake-admission", "intake-ack", "admission_sha256"),
            ("receipt-obligation", "receipt-terminal", "obligation_sha256"),
            ("control-proof", "control-terminal", "control_sha256"),
        ):
            rows = database.execute(
                "SELECT a.record_id,a.document_hash,a.document,"
                "json_extract(CAST(a.document AS TEXT),'$.phase') AS phase,"
                "d.kind AS d_kind,d.record_id AS d_record_id,"
                "d.request_hash AS d_request_hash,d.document AS d_document,"
                "d.binding AS d_binding,d.document_hash AS d_document_hash,"
                "d.recorded_at_ms AS d_recorded_at_ms "
                "FROM tribe_records a LEFT JOIN tribe_records d "
                "ON d.kind=? AND d.record_id=a.record_id WHERE a.kind=?",
                (completed, kind),
            )
            for row in rows:
                source = bytes(row["document"])
                if hashlib.sha256(source).hexdigest() != row["document_hash"]:
                    raise ValueError("tribe_record_corrupt")
                done = None
                if row["d_kind"] is not None:
                    done = self._checked(
                        {
                            name: row["d_" + name]
                            for name in (
                                "kind",
                                "record_id",
                                "request_hash",
                                "document",
                                "binding",
                                "document_hash",
                                "recorded_at_ms",
                            )
                        }
                    )
                    if done.get(digest_field) != row["document_hash"]:
                        done = None
                    if done is not None:
                        if (
                            kind == "receipt-obligation"
                            and done.get("state")
                            not in {
                                "recipient-intake",
                                "refused",
                                "expired",
                            }
                        ) or (
                            kind == "control-proof"
                            and done.get("state") != "receipt-projected"
                        ):
                            done = None
                        elif kind == "intake-admission":
                            ack = json.loads(unb64url(done["response"]))
                            if (
                                ack.get("status") != "accepted"
                                or ack.get("outcome") != "recipient-intake"
                            ):
                                done = None
                    if done is not None and kind == "receipt-obligation":
                        receipt = database.execute(
                            "SELECT * FROM tribe_records WHERE kind='receipt' "
                            "AND record_id=?",
                            (row["record_id"],),
                        ).fetchone()
                        if receipt is None:
                            done = None
                        else:
                            self._checked(receipt)
                            if done.get("receipt_sha256") != receipt["document_hash"]:
                                done = None
                if done is None:
                    control = kind == "control-proof" or (
                        kind == "intake-admission" and row["phase"] == "evidence"
                    )
                    pool = "control" if control else "message"
                    capacity[pool + "-bytes"] += len(source)
                    name = pool + "-ack" if kind == "intake-admission" else kind
                    capacity[name] += 1
        return capacity

    def commit_intake(
        self,
        *,
        request_id: str,
        admission: Mapping[str, Any],
        message: Mapping[str, Any],
        resolution: Mapping[str, Any],
        acceptance: Callable[[int], None],
        obligation: Callable[[int, bool], dict[str, Any]],
        max_pending: int = 64,
        max_bytes: int = 32 * 1024 * 1024,
    ) -> dict[str, Any]:
        """One signed request/readable intake/receipt obligation commit.

        The owning lane supplies authenticated data and an acceptance guard.
        Deduplication, first observation and capacity are serialized here, not
        inferred from handler slots or a stale caller's timestamp.
        """
        identifier = message["event_id"]
        request_hash = hashlib.sha256(canonical_bytes(admission)).hexdigest()
        inbox = {"message": dict(message), "resolution": dict(resolution)}
        inbox_hash = hashlib.sha256(canonical_bytes(inbox)).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT * FROM tribe_records WHERE kind='intake-admission' "
                    "AND record_id=?",
                    (request_id,),
                ).fetchone()
                received = database.execute(
                    "SELECT * FROM tribe_records WHERE kind='inbox' AND record_id=?",
                    (identifier,),
                ).fetchone()
                retained = database.execute(
                    "SELECT * FROM tribe_records WHERE kind='receipt-obligation' "
                    "AND record_id=?",
                    (identifier,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise ValueError("tribe_record_request_conflict")
                    checked = self._checked(existing)
                    if received is None or retained is None:
                        raise ValueError("tribe_intake_commit_incomplete")
                    if received["request_hash"] != inbox_hash:
                        raise ValueError("tribe_record_request_conflict")
                    self._checked(received)
                    self._checked(retained)
                    database.commit()
                    return checked
                now = self.clock()
                acceptance(now)
                if received is not None:
                    if received["request_hash"] != inbox_hash:
                        raise ValueError("tribe_record_request_conflict")
                    self._checked(received)
                expected = None
                if retained is None:
                    first = now if received is None else int(received["recorded_at_ms"])
                    expected = obligation(first, received is not None)
                capacity = self._pending_capacity(database)
                raw_size = len(
                    canonical_bytes({**dict(admission), "received_at_ms": now})
                )
                if expected is not None:
                    raw_size += len(canonical_bytes(expected))
                if (
                    capacity["message-ack"] >= max_pending
                    or capacity["message-bytes"] + raw_size > max_bytes
                    or (
                        retained is None
                        and capacity["receipt-obligation"] >= max_pending
                    )
                ):
                    raise TribeControlCapacityError("tribe_control_capacity")
                if retained is None:
                    assert expected is not None
                    self._reserve_in_transaction(
                        database,
                        "receipt-obligation",
                        identifier,
                        hashlib.sha256(canonical_bytes(expected)).hexdigest(),
                        lambda: expected,
                    )
                else:
                    self._checked(retained)
                self._reserve_in_transaction(
                    database, "inbox", identifier, inbox_hash, lambda: inbox
                )
                result = self._reserve_in_transaction(
                    database,
                    "intake-admission",
                    request_id,
                    request_hash,
                    lambda: {**dict(admission), "received_at_ms": now},
                )
                database.commit()
                return result
            except BaseException:
                if database.in_transaction:
                    database.rollback()
                raise

    def commit_control(
        self,
        *,
        request_id: str,
        admission: Mapping[str, Any],
        proof: Mapping[str, Any],
        acceptance: Callable[[int], None],
        max_pending: int = 64,
        max_bytes: int = 32 * 1024 * 1024,
    ) -> dict[str, Any]:
        """Atomically retain a validated control frame and its projection intent."""
        digest = hashlib.sha256(canonical_bytes(admission)).hexdigest()
        proof_digest = hashlib.sha256(canonical_bytes(proof)).hexdigest()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT * FROM tribe_records WHERE kind='intake-admission' "
                    "AND record_id=?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != digest:
                        raise ValueError("tribe_record_request_conflict")
                    stored = database.execute(
                        "SELECT * FROM tribe_records WHERE kind='control-proof' "
                        "AND record_id=?",
                        (request_id,),
                    ).fetchone()
                    if stored is None or stored["request_hash"] != proof_digest:
                        raise ValueError("tribe_intake_commit_incomplete")
                    self._checked(stored)
                    result = self._checked(existing)
                else:
                    now = self.clock()
                    acceptance(now)
                    capacity = self._pending_capacity(database)
                    if (
                        capacity["control-ack"] >= max_pending
                        or capacity["control-proof"] >= max_pending
                        or capacity["control-bytes"]
                        + len(
                            canonical_bytes({**dict(admission), "received_at_ms": now})
                        )
                        + len(canonical_bytes(proof))
                        > max_bytes
                    ):
                        raise TribeControlCapacityError("tribe_control_capacity")
                    self._reserve_in_transaction(
                        database,
                        "control-proof",
                        request_id,
                        proof_digest,
                        lambda: dict(proof),
                    )
                    result = self._reserve_in_transaction(
                        database,
                        "intake-admission",
                        request_id,
                        digest,
                        lambda: {**dict(admission), "received_at_ms": now},
                    )
                database.commit()
                return result
            except BaseException:
                if database.in_transaction:
                    database.rollback()
                raise

    def get(
        self, kind: str, record_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any] | None:
        with self._database(deadline_ns=deadline_ns) as database:
            row = database.execute(
                "SELECT * FROM tribe_records WHERE kind=? AND record_id=?",
                (kind, record_id),
            ).fetchone()
        return None if row is None else self._checked(row)

    def intake_page(
        self,
        *,
        after: int = 0,
        limit: int = 32,
        max_bytes: int = 32 * 1024 * 1024,
        deadline_ns: int | None = None,
    ) -> dict[str, Any]:
        """Bound signed admission loads before decoding large retained frames."""
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 64
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= 32 * 1024 * 1024
        ):
            raise ValueError("tribe_intake_page_invalid")
        selected, consumed = [], 0
        with self._database() as database:
            headers = database.execute(
                "SELECT sequence,length(document) AS size FROM tribe_records "
                "WHERE kind='intake-admission' AND sequence>? "
                "ORDER BY sequence LIMIT ?",
                (after, limit + 1),
            ).fetchall()
            for header in headers[:limit]:
                if consumed + header["size"] > max_bytes or (
                    deadline_ns is not None and time.monotonic_ns() >= deadline_ns
                ):
                    break
                row = database.execute(
                    "SELECT * FROM tribe_records WHERE kind='intake-admission' "
                    "AND sequence=? AND length(document)=?",
                    (header["sequence"], header["size"]),
                ).fetchone()
                if row is None:
                    raise ValueError("tribe_record_corrupt")
                selected.append(
                    {"sequence": row["sequence"], "admission": self._checked(row)}
                )
                consumed += header["size"]
        return {
            "items": selected,
            "next_after": after if not selected else selected[-1]["sequence"],
            "has_more": len(headers) > len(selected),
        }

    def transport_result(
        self, request_id: str, *, deadline_ns: int | None = None
    ) -> dict[str, Any] | None:
        with self._database(deadline_ns=deadline_ns) as database:
            row = database.execute(
                "SELECT * FROM tribe_records WHERE kind='transport-result' "
                "AND json_extract(CAST(document AS TEXT),'$.request_id')=? "
                "ORDER BY recorded_at_ms DESC, sequence DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        return None if row is None else self._checked(row)

    def bind_egress(
        self,
        controller: MandatoryEgressController,
        *,
        catalog_id: str,
        authorize: Callable[[OperationBinding], bool],
    ) -> None:
        self.egress, self.catalog_id = controller, catalog_id
        controller.register_catalog(
            catalog_id=catalog_id,
            path=self.path,
            resolve=self._native,
            authorize=lambda binding: authorize(binding),
        )
        controller.register_path("tribe-message-request", catalog_id)
        controller.register_path("tribe-receipt-request", catalog_id)

    def _native(self, locator: str) -> bytes:
        value = self.get("native", locator)
        if value is None:
            raise ValueError("tribe_native_missing")
        return unb64url(value["native"])

    def admit(
        self,
        record_id: str,
        native: bytes,
        *,
        path_id: str,
        projection: Any,
        deadline_ms: int,
        authority_head: str,
    ) -> OperationBinding:
        if self.egress is None or self.catalog_id is None:
            raise ValueError("tribe_egress_required")
        document = {
            "native": b64url(native),
            "projection": projection,
            "deadline_ms": deadline_ms,
            "authority_head": authority_head,
        }
        if str(uuid.UUID(record_id)) != record_id:
            raise ValueError("tribe_record_id_invalid")
        existing = self.get("native", record_id)
        if existing is not None:
            if existing != document:
                raise ValueError("tribe_record_request_conflict")
            try:
                return self.egress.binding(self.catalog_id, record_id)
            except NativeEgressError as exception:
                if str(exception) != "egress_operation_missing":
                    raise
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            # Commit the signed carrier and its mandatory visibility obligation
            # together, so a crash cannot strand an untracked native operation.
            self._reserve_in_transaction(
                database,
                "native",
                record_id,
                hashlib.sha256(canonical_bytes(document)).hexdigest(),
                lambda: document,
            )
            binding = self.egress.admit_in_transaction(
                database,
                catalog_id=self.catalog_id,
                path_id=path_id,
                operation_id=record_id,
                locator=record_id,
                native_bytes=native,
                projection=projection,
                deadline_ms=deadline_ms,
                authority_head=authority_head,
            )
            database.commit()
        return binding

    def page(
        self, *, thread_id: str | None = None, after: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValueError("tribe_record_page_invalid")
        if thread_id is not None and str(uuid.UUID(thread_id)) != thread_id:
            raise ValueError("tribe_record_thread_invalid")
        with self._database() as database:
            rows = database.execute(
                "SELECT * FROM tribe_records WHERE kind='inbox' AND sequence>? "
                "AND (? IS NULL OR json_extract(CAST(document AS TEXT), "
                "'$.message.payload.intent.thread_id')=?) ORDER BY sequence LIMIT ?",
                (after, thread_id, thread_id, limit + 1),
            ).fetchall()
        selected = [(row, self._checked(row)) for row in rows]
        page = selected[:limit]
        return {
            "messages": [value["message"] for _, value in page],
            "items": [
                {
                    "inbox_sequence": row["sequence"],
                    "message": value["message"],
                    "evidence": value["resolution"],
                    "admission_version": 3,
                }
                for row, value in page
            ],
            "next_cursor": page[-1][0]["sequence"] if page else after,
            "more": len(selected) > limit,
        }


class MessagingOutboxStore:
    """Owner-local prepared envelopes, separate from inbox and RPC journals."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        self._egress: MandatoryEgressController | None = None
        self._egress_catalog: str | None = None
        self._egress_authorizers: dict[str, Callable[[OperationBinding], bool]] = {}
        with self._database() as database:
            database.execute("""
                CREATE TABLE IF NOT EXISTS messaging_outbox (
                    owner TEXT NOT NULL,
                    send_id TEXT NOT NULL,
                    plan BLOB NOT NULL,
                    evidence BLOB,
                    message BLOB,
                    PRIMARY KEY(owner, send_id),
                    CHECK ((evidence IS NULL) = (message IS NULL))
                )
            """)
            database.execute("""
                CREATE TABLE IF NOT EXISTS messaging_transport_stages (
                    owner TEXT NOT NULL,
                    send_id TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK (phase IN ('evidence', 'message')),
                    binding BLOB NOT NULL,
                    request BLOB NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    transport_status TEXT NOT NULL CHECK (transport_status IN
                        ('prepared', 'pending', 'recipient-intake',
                         'refused', 'hub-accepted')),
                    result_sha256 TEXT,
                    response BLOB,
                    PRIMARY KEY(owner, send_id, phase)
                )
            """)

    def _record_failure(
        self, owner: str, send_id: str, phase: str, code: str, at_ms: int
    ) -> None:
        write_diagnostic(
            self.path, "route", "\0".join((owner, send_id, phase)), code, at_ms
        )

    def _failure(self, owner: str, send_id: str, phase: str) -> dict[str, Any] | None:
        return read_diagnostic(self.path, "route", "\0".join((owner, send_id, phase)))

    def bind_egress(
        self,
        controller: MandatoryEgressController,
        *,
        catalog_id: str,
        owner: str,
        authorize: Callable[[OperationBinding], bool],
    ) -> None:
        if self._egress is None:
            self._egress = controller
            self._egress_catalog = catalog_id
            controller.register_catalog(
                catalog_id=catalog_id,
                path=self.path,
                resolve=self._resolve_egress,
                authorize=lambda binding: self._authorize_egress(binding),
            )
            controller.register_path("messaging-evidence-request", catalog_id)
            controller.register_path("messaging-message-request", catalog_id)
        elif self._egress is not controller or self._egress_catalog != catalog_id:
            raise ValueError("messaging_egress_already_bound")
        if owner in self._egress_authorizers:
            raise ValueError("messaging_egress_already_bound")
        self._egress_authorizers[owner] = authorize

    def _authorize_egress(self, binding: OperationBinding) -> bool:
        try:
            owner, _send_id, _phase = binding.locator.split("\0")
            authorize = self._egress_authorizers[owner]
        except (ValueError, KeyError):
            return False
        return authorize(binding) is True

    def _resolve_egress(self, locator: str) -> bytes:
        try:
            owner, send_id, phase = locator.split("\0")
        except ValueError:
            raise ValueError("messaging_egress_locator_invalid") from None
        with self._database() as database:
            row = database.execute(
                "SELECT request FROM messaging_transport_stages "
                "WHERE owner=? AND send_id=? AND phase=?",
                (owner, send_id, phase),
            ).fetchone()
        if row is None:
            raise ValueError("messaging_transport_missing")
        return bytes(row[0])

    def _inspection_config_digest(self, owner: str, send_id: str) -> str:
        """Read the frozen two-stage selection; authorization belongs to caller."""
        with self._database() as database:
            rows = database.execute(
                "SELECT phase, binding FROM messaging_transport_stages "
                "WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchall()
        if {row["phase"] for row in rows} != {"evidence", "message"}:
            raise ValueError("messaging_transport_missing")
        try:
            values = [
                json.loads(bytes(row["binding"]))["config_digest"] for row in rows
            ]
        except (ValueError, KeyError, TypeError):
            raise ValueError("messaging_transport_conflict") from None
        if (
            any(
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in values
            )
            or len(set(values)) != 1
        ):
            raise ValueError("messaging_transport_conflict")
        return str(values[0])

    def _transport_stages(
        self,
        owner: str,
        send_id: str,
        bindings: Mapping[str, Mapping[str, Any]],
        prepare: Callable[[str], bytes],
        *,
        projections: Mapping[str, Mapping[str, Any]],
        deadline_ms: int,
        authority_head: str,
        create: bool = True,
    ) -> dict[str, dict[str, Any]]:
        """Bind both stages atomically; local-only prepare is not called on retry."""
        if self._egress is None or self._egress_catalog is None:
            raise ValueError("messaging_egress_unbound")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE" if create else "BEGIN")
            if (
                database.execute(
                    "SELECT 1 FROM messaging_outbox WHERE owner=? AND send_id=? "
                    "AND evidence IS NOT NULL",
                    (owner, send_id),
                ).fetchone()
                is None
            ):
                raise ValueError("messaging_outbox_missing")
            stages = {}
            for phase, binding in bindings.items():
                encoded = canonical_bytes(binding)
                row = database.execute(
                    "SELECT binding, request, request_sha256, transport_status, "
                    "response, result_sha256 "
                    "FROM messaging_transport_stages "
                    "WHERE owner=? AND send_id=? AND phase=?",
                    (owner, send_id, phase),
                ).fetchone()
                if row is not None:
                    if (
                        bytes(row["binding"]) != encoded
                        or hashlib.sha256(row["request"]).hexdigest()
                        != row["request_sha256"]
                    ):
                        raise ValueError("messaging_transport_conflict")
                    raw, status = bytes(row["request"]), row["transport_status"]
                else:
                    if not create:
                        raise ValueError("messaging_transport_missing")
                    raw, status = prepare(phase), "prepared"
                    database.execute(
                        "INSERT INTO messaging_transport_stages "
                        "(owner, send_id, phase, binding, request, "
                        "request_sha256, transport_status) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            owner,
                            send_id,
                            phase,
                            encoded,
                            raw,
                            hashlib.sha256(raw).hexdigest(),
                            status,
                        ),
                    )
                stages[phase] = {
                    "request": raw,
                    "transport_status": status,
                    "response": None if row is None else row["response"],
                    "result_sha256": None if row is None else row["result_sha256"],
                }
                if not create:
                    continue
                self._egress.admit_in_transaction(
                    database,
                    catalog_id=self._egress_catalog,
                    path_id=f"messaging-{phase}-request",
                    operation_id=f"{send_id}:{phase}",
                    locator="\0".join((owner, send_id, phase)),
                    native_bytes=raw,
                    projection=(
                        json.loads(existing_projection[0])
                        if (
                            existing_projection := database.execute(
                                "SELECT projection_json "
                                "FROM mandatory_egress_operations "
                                "WHERE operation_id=?",
                                (f"{send_id}:{phase}",),
                            ).fetchone()
                        )
                        is not None
                        else projections[phase]
                    ),
                    deadline_ms=deadline_ms,
                    authority_head=authority_head,
                )
        return stages

    def _transport_status(
        self,
        owner: str,
        send_id: str,
        phase: str,
        *,
        result: Mapping[str, Any] | None = None,
        response: bytes | None = None,
    ) -> str:
        """Commit pending before I/O; atomically retain authenticated response proof."""
        if (result is None) != (response is None):
            raise ValueError("messaging_transport_response_missing")
        status = "pending" if result is None else result["outcome"]
        digest = (
            None
            if result is None
            else hashlib.sha256(canonical_bytes(result)).hexdigest()
        )
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE messaging_transport_stages "
                "SET transport_status=?, result_sha256=?, response=? "
                "WHERE owner=? AND send_id=? AND phase=? "
                "AND transport_status IN ('prepared', 'pending')",
                (status, digest, response, owner, send_id, phase),
            )
            row = database.execute(
                "SELECT transport_status FROM messaging_transport_stages "
                "WHERE owner=? AND send_id=? AND phase=?",
                (owner, send_id, phase),
            ).fetchone()
            if row is None:
                raise ValueError("messaging_transport_missing")
            return str(row["transport_status"])

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _prepare_path(self.path)
        database = sqlite3.connect(self.path, timeout=5)
        try:
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            with database:
                yield database
        finally:
            database.close()

    def _reserve(
        self, owner: str, send_id: str, plan: dict[str, Any]
    ) -> dict[str, Any]:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
            if row is not None:
                existing = dict(json.loads(row["plan"]))
                if any(
                    existing[key] != plan[key]
                    for key in (
                        "client_id",
                        "request_hash",
                        "policy_hash",
                        "origin",
                    )
                ):
                    raise ValueError("messaging_send_conflict")
                return existing
            database.execute(
                "INSERT INTO messaging_outbox (owner, send_id, plan) VALUES (?, ?, ?)",
                (owner, send_id, canonical_bytes(plan)),
            )
        return plan

    def _carrier(
        self,
        owner: str,
        logical_send_id: str,
        logical_plan: Mapping[str, Any],
        *,
        now: int,
        max_ttl_ms: int,
    ) -> tuple[str, dict[str, Any]]:
        """Return the live immutable carrier or durably reserve its successor."""

        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            rows = database.execute(
                "SELECT send_id, plan FROM messaging_outbox WHERE owner=?",
                (owner,),
            ).fetchall()
            carriers: list[tuple[int, str, dict[str, Any]]] = []
            for row in rows:
                plan = dict(json.loads(row["plan"]))
                row_logical_id = plan.get("logical_send_id", row["send_id"])
                if row_logical_id != logical_send_id:
                    continue
                generation = int(plan.get("carrier_generation", 1))
                carriers.append((generation, str(row["send_id"]), plan))
            if not carriers:
                raise ValueError("messaging_outbox_missing")
            carriers.sort(key=lambda item: item[0])
            if [item[0] for item in carriers] != list(range(1, len(carriers) + 1)):
                raise ValueError("messaging_carrier_conflict")
            generation, carrier_send_id, carrier_plan = carriers[-1]
            if now < int(carrier_plan["issued_at_ms"]):
                raise ValueError("messaging_authorization_not_yet_valid")
            # This is only a selection hint, not delivery evidence. The delivery
            # facade must authenticate both retained responses before returning
            # success. Completed operations need no fresh disclosure authority.
            if self._recorded_intake(database, owner, carrier_send_id):
                return carrier_send_id, carrier_plan
            if now < int(carrier_plan["expires_at_ms"]):
                return carrier_send_id, carrier_plan

            generation += 1
            carrier_send_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"dm.messaging.carrier/v1:{logical_send_id}:{generation}",
                )
            )
            carrier_plan = dict(logical_plan)
            carrier_plan.update(
                {
                    "logical_send_id": logical_send_id,
                    "carrier_generation": generation,
                    "issued_at_ms": now,
                    "expires_at_ms": now + max_ttl_ms,
                    "message_authorization_id": str(
                        uuid.uuid5(uuid.UUID(carrier_send_id), "message-authorization")
                    ),
                    "evidence_authorization_id": str(
                        uuid.uuid5(uuid.UUID(carrier_send_id), "evidence-authorization")
                    ),
                }
            )
            database.execute(
                "INSERT INTO messaging_outbox (owner, send_id, plan) VALUES (?, ?, ?)",
                (owner, carrier_send_id, canonical_bytes(carrier_plan)),
            )
            return carrier_send_id, carrier_plan

    @staticmethod
    def _recorded_intake(
        database: sqlite3.Connection, owner: str, send_id: str
    ) -> bool:
        rows = database.execute(
            "SELECT phase, transport_status FROM messaging_transport_stages "
            "WHERE owner=? AND send_id=?",
            (owner, send_id),
        ).fetchall()
        return {(row[0], row[1]) for row in rows} == {
            ("evidence", "recipient-intake"),
            ("message", "recipient-intake"),
        }

    def _intake_recorded(self, owner: str, send_id: str) -> bool:
        """Selection hint only; retained authenticated responses remain required."""
        with self._database() as database:
            return self._recorded_intake(database, owner, send_id)

    def _inspection_pair(
        self,
        owner: str,
        logical_send_id: str,
        *,
        expected: Mapping[str, Any],
        now: int,
    ) -> tuple[bytes, bytes]:
        """Latest fully retained transport pair; never reserve or renew a carrier."""

        with self._database() as database:
            database.execute("BEGIN")
            rows = database.execute(
                "SELECT send_id, plan, evidence, message FROM messaging_outbox "
                "WHERE owner=?",
                (owner,),
            ).fetchall()
            carriers = []
            for row in rows:
                plan = json.loads(row["plan"])
                if plan.get("logical_send_id", row["send_id"]) != logical_send_id:
                    continue
                generation = plan.get("carrier_generation", 1)
                carrier_id = (
                    logical_send_id
                    if generation == 1
                    else str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"dm.messaging.carrier/v1:{logical_send_id}:{generation}",
                        )
                    )
                )
                if (
                    type(generation) is not int
                    or generation < 1
                    or row["send_id"] != carrier_id
                    or any(plan.get(key) != value for key, value in expected.items())
                    or type(plan.get("issued_at_ms")) is not int
                    or type(plan.get("expires_at_ms")) is not int
                    or not 0 <= plan["issued_at_ms"] < plan["expires_at_ms"]
                    or now < plan["issued_at_ms"]
                ):
                    raise ValueError("messaging_carrier_conflict")
                phases = database.execute(
                    "SELECT phase FROM messaging_transport_stages "
                    "WHERE owner=? AND send_id=?",
                    (owner, row["send_id"]),
                ).fetchall()
                if phases and {item[0] for item in phases} != {"evidence", "message"}:
                    raise ValueError("messaging_transport_conflict")
                complete = row["evidence"] is not None and bool(phases)
                carriers.append((generation, row, complete))
            carriers.sort(key=lambda item: item[0])
            if [item[0] for item in carriers] != list(range(1, len(carriers) + 1)):
                raise ValueError("messaging_carrier_conflict")
            for _, row, complete in reversed(carriers):
                if complete:
                    return bytes(row["evidence"]), bytes(row["message"])
        raise ValueError("messaging_transport_missing")

    def _carrier_for_envelopes(
        self,
        owner: str,
        logical_send_id: str,
        envelopes: tuple[bytes, bytes],
    ) -> str:
        with self._database() as database:
            rows = database.execute(
                "SELECT send_id, plan FROM messaging_outbox "
                "WHERE owner=? AND evidence=? AND message=?",
                (owner, *envelopes),
            ).fetchall()
        matches = [
            str(row["send_id"])
            for row in rows
            if json.loads(row["plan"]).get("logical_send_id", row["send_id"])
            == logical_send_id
        ]
        if len(matches) != 1:
            raise ValueError("messaging_carrier_conflict")
        return matches[0]

    def _check_client(self, owner: str, send_id: str, client_id: str) -> None:
        with self._database() as database:
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is None or json.loads(row["plan"])["client_id"] != client_id:
            raise ValueError("messaging_send_conflict")

    def _check_time(self, owner: str, send_id: str, now: int) -> None:
        with self._database() as database:
            row = database.execute(
                "SELECT plan FROM messaging_outbox WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is not None:
            plan = json.loads(row["plan"])
            if now >= plan["expires_at_ms"]:
                raise ValueError("messaging_authorization_expired")
            if now < plan["issued_at_ms"]:
                raise ValueError("messaging_authorization_not_yet_valid")

    def _prepared(self, owner: str, send_id: str) -> tuple[bytes, bytes] | None:
        with self._database() as database:
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox "
                "WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
        if row is None or row["evidence"] is None:
            return None
        return bytes(row["evidence"]), bytes(row["message"])

    def _commit(
        self, owner: str, send_id: str, envelopes: tuple[bytes, bytes]
    ) -> tuple[bytes, bytes]:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "UPDATE messaging_outbox SET evidence=?, message=? "
                "WHERE owner=? AND send_id=? AND evidence IS NULL",
                (*envelopes, owner, send_id),
            )
            row = database.execute(
                "SELECT evidence, message FROM messaging_outbox "
                "WHERE owner=? AND send_id=?",
                (owner, send_id),
            ).fetchone()
            if row is None:
                raise ValueError("messaging_outbox_missing")
            result = bytes(row["evidence"]), bytes(row["message"])
        return result


class MessagingInboxStore:
    """Internal materialization sink. Receive through MessagingChannel only."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        with self._database() as database:
            database.executescript("""
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    bytes_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS identities (
                    event_id TEXT PRIMARY KEY,
                    being_ref TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    bytes_hash TEXT NOT NULL,
                    UNIQUE(being_ref, incarnation_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    message_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    event BLOB NOT NULL,
                    envelope BLOB NOT NULL,
                    PRIMARY KEY(message_id, authorization_id)
                );
                CREATE TABLE IF NOT EXISTS inbox (
                    inbox_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id TEXT NOT NULL UNIQUE,
                    policy_hash TEXT NOT NULL,
                    message BLOB NOT NULL,
                    evidence BLOB NOT NULL,
                    envelope BLOB NOT NULL,
                    admission_version INTEGER NOT NULL DEFAULT 1
                        CHECK(admission_version IN (1, 2))
                );
            """)

    @staticmethod
    def _has_admission_version(database: sqlite3.Connection) -> bool:
        return any(
            row["name"] == "admission_version"
            for row in database.execute("PRAGMA table_info(inbox)")
        )

    @classmethod
    def upgrade_admission_path(cls, path: Path) -> None:
        """Durably classify all existing rows as V1 before V2 can be admitted."""

        path = path.absolute()
        with (
            closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as database,
            database,
        ):
            database.row_factory = sqlite3.Row
            database.execute("BEGIN IMMEDIATE")
            if not cls._has_admission_version(database):
                database.execute(
                    "ALTER TABLE inbox ADD COLUMN admission_version INTEGER NOT NULL "
                    "DEFAULT 1 CHECK(admission_version IN (1, 2))"
                )

    def upgrade_admission_v2(self) -> None:
        self.upgrade_admission_path(self.path)

    def _admission_version(self, message_id: str, current: int) -> int:
        with self._database() as database:
            if not self._has_admission_version(database):
                return 1
            row = database.execute(
                "SELECT admission_version FROM inbox WHERE message_id=?", (message_id,)
            ).fetchone()
        return current if row is None else int(row["admission_version"])

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        _prepare_path(self.path)
        database = sqlite3.connect(self.path, timeout=5)
        try:
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            with database:
                yield database
        finally:
            database.close()

    @staticmethod
    def _delivery(database: sqlite3.Connection, raw: bytes, *, retain: bool) -> None:
        identifier = json.loads(raw)["delivery_id"]
        digest = hashlib.sha256(raw).hexdigest()
        row = database.execute(
            "SELECT bytes_hash FROM deliveries WHERE delivery_id=?", (identifier,)
        ).fetchone()
        if row is not None and row["bytes_hash"] != digest:
            raise MessagingInboxError("messaging_delivery_conflict")
        if retain and row is None:
            database.execute(
                "INSERT INTO deliveries VALUES (?, ?)", (identifier, digest)
            )

    def _check_delivery(self, raw: bytes) -> None:
        with self._database() as database:
            self._delivery(database, raw, retain=False)

    @staticmethod
    def _identity(database: sqlite3.Connection, event: Mapping[str, Any]) -> None:
        binding = (
            event["event_id"],
            event["being_ref"],
            event["origin"]["incarnation_id"],
            event["sequence"],
            hashlib.sha256(canonical_bytes(event)).hexdigest(),
        )
        rows = database.execute(
            "SELECT * FROM identities WHERE event_id=? OR "
            "(being_ref=? AND incarnation_id=? AND sequence=?)",
            binding[:4],
        ).fetchall()
        if rows:
            if len(rows) != 1 or tuple(rows[0]) != binding:
                raise MessagingInboxError("messaging_event_conflict")
            return
        database.execute("INSERT INTO identities VALUES (?, ?, ?, ?, ?)", binding)

    def _retain_evidence(
        self, event: Mapping[str, Any], raw: bytes, policy_hash: str
    ) -> None:
        payload = event["payload"]
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            self._delivery(database, raw, retain=True)
            self._identity(database, event)
            self._identity(database, payload["resolution_event"])
            existing = database.execute(
                "SELECT event, policy_hash FROM evidence "
                "WHERE message_id=? AND authorization_id=?",
                (payload["message_id"], payload["message_authorization_id"]),
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["event"]) != canonical_bytes(event)
                    or existing["policy_hash"] != policy_hash
                ):
                    raise MessagingInboxError("messaging_evidence_conflict")
                return
            database.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?)",
                (
                    payload["message_id"],
                    payload["message_authorization_id"],
                    policy_hash,
                    canonical_bytes(event),
                    raw,
                ),
            )

    def _evidence(
        self, message_id: str, authorization_id: str, policy_hash: str
    ) -> dict[str, Any] | None:
        with self._database() as database:
            row = database.execute(
                "SELECT event FROM evidence "
                "WHERE message_id=? AND authorization_id=? AND policy_hash=?",
                (message_id, authorization_id, policy_hash),
            ).fetchone()
        return None if row is None else dict(json.loads(row["event"]))

    def _retain_message(
        self,
        message: Mapping[str, Any],
        evidence: Mapping[str, Any],
        raw: bytes,
        policy_hash: str,
        admission_version: int = 1,
    ) -> dict[str, Any]:
        if admission_version not in {1, 2}:
            raise MessagingInboxError("messaging_admission_version_invalid")
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            versioned = self._has_admission_version(database)
            if admission_version == 2 and not versioned:
                raise MessagingInboxError("messaging_admission_migration_required")
            self._delivery(database, raw, retain=True)
            self._identity(database, message)
            existing = database.execute(
                "SELECT * FROM inbox WHERE message_id=?", (message["event_id"],)
            ).fetchone()
            if existing is not None:
                if (
                    bytes(existing["message"]) != canonical_bytes(message)
                    or existing["policy_hash"] != policy_hash
                    or (
                        versioned and existing["admission_version"] != admission_version
                    )
                ):
                    raise MessagingInboxError("messaging_message_conflict")
                return {
                    "inbox_sequence": existing["inbox_sequence"],
                    "message_id": message["event_id"],
                }
            fields = "message_id, policy_hash, message, evidence, envelope"
            values: tuple[Any, ...] = (
                message["event_id"],
                policy_hash,
                canonical_bytes(message),
                canonical_bytes(evidence),
                raw,
            )
            if versioned:
                fields += ", admission_version"
                values += (admission_version,)
            cursor = database.execute(
                f"INSERT INTO inbox ({fields}) VALUES ("
                + ", ".join("?" for _ in values)
                + ")",
                values,
            )
            return {
                "inbox_sequence": cursor.lastrowid,
                "message_id": message["event_id"],
            }

    def _message(self, message_id: str, policy_hash: str) -> dict[str, Any]:
        with self._database() as database:
            admission = (
                "admission_version"
                if self._has_admission_version(database)
                else "1 AS admission_version"
            )
            row = database.execute(
                f"SELECT inbox_sequence, message, evidence, {admission} FROM inbox "
                "WHERE message_id=? AND policy_hash=?",
                (message_id, policy_hash),
            ).fetchone()
        if row is None:
            raise MessagingInboxError("messaging_message_missing")
        return {
            "inbox_sequence": row["inbox_sequence"],
            "admission_version": row["admission_version"],
            "message": json.loads(row["message"]),
            "evidence": json.loads(row["evidence"]),
        }

    def _page(
        self, *, after: int, limit: int, policy_hash: str
    ) -> list[dict[str, Any]]:
        if (
            type(after) is not int
            or not 0 <= after <= 2**53 - 1
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise MessagingInboxError("messaging_page_bounds")
        with self._database() as database:
            admission = (
                "admission_version"
                if self._has_admission_version(database)
                else "1 AS admission_version"
            )
            rows = database.execute(
                f"SELECT inbox_sequence, message, evidence, {admission} FROM inbox "
                "WHERE inbox_sequence>? AND policy_hash=? "
                "ORDER BY inbox_sequence LIMIT ?",
                (after, policy_hash, limit),
            ).fetchall()
        return [
            {
                "inbox_sequence": row["inbox_sequence"],
                "admission_version": row["admission_version"],
                "message": json.loads(row["message"]),
                "evidence": json.loads(row["evidence"]),
            }
            for row in rows
        ]
