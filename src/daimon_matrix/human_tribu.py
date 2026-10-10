"""Passive human-addressed Tribu intake and explicit signed reply intents.

Telegram is the authenticated ingress source, not a human signing authority.
This separate application never writes foreign-message inboxes, loads custody,
starts a harness, reads native histories or selects native conversations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .identity import verify_embodiment_credential
from .mandatory_echo import _record_request, validate_proof_shape
from .operator_rebirth import authority_from_document
from .telegram_mirror import (
    plain_request,
    render_readable_parts,
    validate_plain_response,
)
from .weave import verify_event

MAX_DOCUMENT = 2 * 1024 * 1024
REQUEST_SCHEMA = "dm.tribu-human-request/v1"
REPLY_SCHEMA = "dm.tribu-human-reply/v1"


class HumanTribuError(ValueError):
    """Bounded public error codes; never include credentials or Telegram URLs."""


def json_bytes(value: Any) -> bytes:
    """Transport JSON preserves literal Telegram Unicode, unlike signed JCS.

    Unrelated platform updates may contain finite coordinates. They must not
    poison the transport cursor. Native signatures retain their own strict codec.
    """
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def closed(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise HumanTribuError("invalid_fields")
    return value


def integer(value: Any, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value < 2**53:
        raise HumanTribuError("invalid_integer")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HumanTribuError("duplicate_key")
        result[key] = value
    return result


def document(raw: bytes) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_DOCUMENT:
        raise HumanTribuError("document_size")
    value = json.loads(raw, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise HumanTribuError("invalid_document")
    json_bytes(value)  # Reject nonfinite values and malformed UTF-8.
    return value


def _entity_text(text: str, entity: dict[str, Any]) -> str:
    offset, length = (
        integer(entity.get("offset")),
        integer(entity.get("length"), minimum=1),
    )
    raw = text.encode("utf-16-le")
    if offset + length > len(raw) // 2:
        raise HumanTribuError("invalid_entity")
    try:
        return raw[offset * 2 : (offset + length) * 2].decode("utf-16-le")
    except UnicodeError:
        raise HumanTribuError("invalid_entity") from None


@dataclass(frozen=True)
class Participant:
    """Operator-selected public body authority and private paired-human policy."""

    being_ref: str
    label: str
    human_id: int
    human_name: str
    username: str
    bot_id: int
    origin: Mapping[str, str]
    authority: dict[str, Any]
    token: str
    proof_keys: Mapping[str, bytes]
    enabled: bool = True

    def validate(self) -> None:
        integer(self.human_id, minimum=1)
        integer(self.bot_id, minimum=1)
        if (
            type(self.enabled) is not bool
            or not re.fullmatch(r"[A-Za-z0-9_]{5,32}", self.username)
            or not re.fullmatch(r"[a-f0-9]{64}", self.token)
            or not 0 < len(self.label) < 129
            or not 0 < len(self.human_name) < 129
        ):
            raise HumanTribuError("participant_invalid")
        authority = authority_from_document(self.authority)
        if authority.manifest.being_ref != self.being_ref:
            raise HumanTribuError("participant_authority_mismatch")
        authority.validate_origin(self.origin, require_active=True)


class HumanTribu:
    """One durable application, independent of all native session generations."""

    def __init__(
        self,
        path: Path,
        *,
        bot_id: int,
        chat_id: int,
        participants: Callable[[], list[Participant]],
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        self.path = path
        self.bot_id, self.chat_id = bot_id, chat_id
        self.participants, self.clock = participants, clock
        self.lock = threading.RLock()
        with closing(self._db()) as db, db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value"
                " TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS updates (id INTEGER PRIMARY "
                "KEY,hash TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY,"
                "human INTEGER NOT NULL,parent INTEGER NOT NULL,record TEXT NOT NULL,"
                "received_at_ms INTEGER NOT NULL,resolved INTEGER NOT NULL);"
                "CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY "
                "KEY,being TEXT NOT NULL,"
                "platform_id INTEGER NOT NULL,latest TEXT NOT NULL,stamp "
                "INTEGER NOT NULL,"
                "update_id INTEGER NOT NULL);"
                "CREATE TABLE IF NOT EXISTS revisions (sequence INTEGER "
                "PRIMARY KEY AUTOINCREMENT,"
                "message TEXT NOT NULL,revision TEXT NOT NULL,record TEXT NOT NULL,"
                "eligible INTEGER NOT NULL,UNIQUE(message,revision));"
                "CREATE TABLE IF NOT EXISTS exposures (message TEXT NOT "
                "NULL,revision TEXT NOT NULL,"
                "at_ms INTEGER NOT NULL,PRIMARY KEY(message,revision));"
                "CREATE TABLE IF NOT EXISTS replies (id TEXT PRIMARY "
                "KEY,being TEXT NOT NULL,"
                "hash TEXT NOT NULL,source TEXT NOT NULL,revision TEXT NOT "
                "NULL,record TEXT NOT NULL);"
                "CREATE INDEX IF NOT EXISTS reply_source ON "
                "replies(being,source,revision);"
                "CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY "
                "KEY,being TEXT NOT NULL,"
                "event_id TEXT NOT NULL,event_hash TEXT NOT NULL,text TEXT NOT NULL,"
                "proof TEXT NOT NULL);"
            )
            identity = {
                "schema": "dm.tribu-human-store/v1",
                "bot_id": bot_id,
                "chat_id": chat_id,
            }
            row = db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if row is not None and json.loads(row[0]) != identity:
                raise HumanTribuError("store_identity_mismatch")
            db.execute(
                "INSERT OR IGNORE INTO meta VALUES ('identity',?)",
                (json_bytes(identity).decode(),),
            )
            db.execute(
                "INSERT OR IGNORE INTO meta VALUES ('start_ms',?)", (str(clock()),)
            )

    def _db(self) -> sqlite3.Connection:
        # Configured owner-private directory; refuse symlinks and shared files.
        parent = self.path.parent.lstat()
        if (
            self.path.parent.is_symlink()
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise HumanTribuError("store_directory_untrusted")
        fd = os.open(
            self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise HumanTribuError("store_file_untrusted")
        finally:
            os.close(fd)
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        return db

    def _people(self) -> list[Participant]:
        rows = self.participants()
        for row in rows:
            row.validate()
        if len({row.being_ref for row in rows}) != len(rows) or len(
            {row.token for row in rows}
        ) != len(rows):
            raise HumanTribuError("participant_conflict")
        if len({row.username.lower() for row in rows}) != len(rows):
            raise HumanTribuError("target_conflict")
        return rows

    def authenticate(self, token: str) -> Participant:
        for row in self._people():
            if hmac.compare_digest(row.token, token) and row.enabled:
                return row
        raise HumanTribuError("unauthorized")

    def status(self) -> dict[str, Any]:
        with self.lock, closing(self._db()) as db:
            meta = dict(db.execute("SELECT key,value FROM meta"))
            return {
                "schema": "dm.tribu-human-status/v1",
                "start_ms": int(meta["start_ms"]),
                "last_update_id": None if "offset" not in meta else int(meta["offset"]),
                "initial_boundary": (
                    "pending-updates-at-start; earlier history not claimed"
                ),
                "automatic_inference": False,
            }

    def _targets(
        self, db: sqlite3.Connection, message: dict[str, Any], people: list[Participant]
    ) -> set[str]:
        text = message.get("text", message.get("caption", ""))
        if not isinstance(text, str):
            raise HumanTribuError("invalid_text")
        targets: set[str] = set()
        entities = message.get("entities", message.get("caption_entities", []))
        if not isinstance(entities, list) or len(entities) > 256:
            raise HumanTribuError("invalid_entities")
        for entity in entities:
            if not isinstance(entity, dict):
                raise HumanTribuError("invalid_entity")
            selected = _entity_text(text, entity)
            if entity.get("type") == "mention":
                matches = [
                    p for p in people if selected.lower() == "@" + p.username.lower()
                ]
                targets.update(p.being_ref for p in matches)
            elif entity.get("type") == "text_mention":
                user = entity.get("user", {})
                targets.update(
                    p.being_ref
                    for p in people
                    if user.get("id") == p.bot_id and user.get("is_bot") is True
                )
        parent = message.get("reply_to_message")
        if isinstance(parent, dict) and type(parent.get("message_id")) is int:
            row = db.execute(
                "SELECT being FROM posts WHERE id=?", (parent["message_id"],)
            ).fetchone()
            if row is not None:
                targets.add(row[0])
        return targets

    def ingest(self, update: dict[str, Any]) -> dict[str, Any]:
        ident = integer(update.get("update_id"))
        raw_hash = digest(update)
        people = self._people()
        with self.lock, closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT hash FROM updates WHERE id=?", (ident,)).fetchone()
            pending = db.execute(
                "SELECT parent,received_at_ms,resolved FROM pending WHERE id=?",
                (ident,),
            ).fetchone()
            if old is not None:
                if old[0] != raw_hash:
                    raise HumanTribuError("update_conflict")
                if (
                    pending is None
                    or pending[2]
                    or db.execute(
                        "SELECT 1 FROM posts WHERE id=?", (pending[0],)
                    ).fetchone()
                    is None
                ):
                    return {"duplicate": True, "retained": 0}
            message = update.get("edited_message", update.get("message"))
            retained = 0
            if (
                isinstance(message, dict)
                and isinstance(message.get("chat"), dict)
                and type(message["chat"].get("id")) is int
                and message["chat"]["id"] == self.chat_id
                and message["chat"].get("type") == "supergroup"
            ):
                actor = message.get("from", {})
                forwarded = any(
                    key in message
                    for key in (
                        "forward_origin",
                        "forward_date",
                        "forward_from",
                        "forward_from_chat",
                    )
                )
                if (
                    isinstance(actor, dict)
                    and type(actor.get("id")) is int
                    and actor.get("is_bot") is False
                    and not forwarded
                    and "sender_chat" not in message
                ):
                    targets = self._targets(db, message, people)
                    parent_id = message.get("reply_to_message", {}).get("message_id")
                    if (
                        type(parent_id) is int
                        and parent_id > 0
                        and any(p.human_id == actor["id"] and p.enabled for p in people)
                        and db.execute(
                            "SELECT 1 FROM posts WHERE id=?", (parent_id,)
                        ).fetchone()
                        is None
                    ):
                        db.execute(
                            "INSERT OR IGNORE INTO pending VALUES(?,?,?,?,?,0)",
                            (
                                ident,
                                actor["id"],
                                parent_id,
                                json_bytes(update).decode(),
                                self.clock(),
                            ),
                        )
                    platform_id = integer(message.get("message_id"), minimum=1)
                    stamp = integer(message.get("edit_date", message.get("date")))
                    for person in people:
                        if actor.get("id") != person.human_id or not person.enabled:
                            continue
                        source_id = digest(
                            [self.bot_id, self.chat_id, platform_id, person.being_ref]
                        )
                        previous = db.execute(
                            "SELECT latest,stamp,update_id FROM messages WHERE id=?",
                            (source_id,),
                        ).fetchone()
                        eligible = person.being_ref in targets
                        if not eligible and previous is None:
                            continue
                        revision = digest(message)
                        parent = message.get("reply_to_message", {})
                        context = self._context(db, parent.get("message_id"), people)
                        record = {
                            "schema": REQUEST_SCHEMA,
                            "id": source_id,
                            "revision": revision,
                            "being_ref": person.being_ref,
                            "human": {
                                "name": person.human_name,
                                "telegram_id": person.human_id,
                            },
                            "source": {
                                "provider": "telegram",
                                "bot_id": self.bot_id,
                                "chat_id": self.chat_id,
                                "message_id": platform_id,
                                "update_id": ident,
                                "date": message.get("date"),
                                "edit_date": message.get("edit_date"),
                                "topic_id": (
                                    message.get("message_thread_id")
                                    if message.get("is_topic_message") is True
                                    else None
                                ),
                                "thread_root_id": message.get("message_thread_id"),
                                "reply_message_id": message.get(
                                    "reply_to_message", {}
                                ).get("message_id"),
                            },
                            "text": message.get("text", message.get("caption", "")),
                            "entities": message.get(
                                "entities", message.get("caption_entities", [])
                            ),
                            "attestation": {
                                "kind": "authenticated-telegram-ingress",
                                "received_at_ms": self.clock()
                                if pending is None
                                else pending[1],
                            },
                            "eligible": eligible,
                            "context": context,
                        }
                        raw = json_bytes(record).decode()
                        inserted = db.execute(
                            "INSERT OR IGNORE INTO "
                            "revisions(message,revision,record,eligible) "
                            "VALUES(?,?,?,?)",
                            (source_id, revision, raw, int(eligible)),
                        ).rowcount
                        retained += inserted
                        if previous is None or (stamp, ident) > (
                            previous[1],
                            previous[2],
                        ):
                            db.execute(
                                "INSERT INTO messages VALUES(?,?,?,?,?,?) ON"
                                " CONFLICT(id) DO UPDATE SET "
                                "latest=excluded.latest,stamp=excluded.stamp,update_id=excluded.update_id",
                                (
                                    source_id,
                                    person.being_ref,
                                    platform_id,
                                    revision,
                                    stamp,
                                    ident,
                                ),
                            )
            db.execute("INSERT OR IGNORE INTO updates VALUES(?,?)", (ident, raw_hash))
            if pending is not None:
                db.execute("UPDATE pending SET resolved=1 WHERE id=?", (ident,))
            offset = db.execute("SELECT value FROM meta WHERE key='offset'").fetchone()
            if offset is None or ident > int(offset[0]):
                db.execute(
                    "INSERT INTO meta VALUES('offset',?) ON CONFLICT(key) DO"
                    " UPDATE SET value=excluded.value",
                    (str(ident),),
                )
            return {"duplicate": False, "retained": retained}

    @staticmethod
    def _context(
        db: sqlite3.Connection, parent_id: Any, people: list[Participant]
    ) -> dict[str, Any] | None:
        if type(parent_id) is not int:
            return None
        post = db.execute(
            "SELECT being,event_id,event_hash,text FROM posts WHERE id=?", (parent_id,)
        ).fetchone()
        if post is None:
            return None
        return {
            "kind": "verified-native-publication",
            "sender": next(
                (p.label for p in people if p.being_ref == post[0]), post[0]
            ),
            "event_id": post[1],
            "event_digest": post[2],
            "text": post[3],
            "message_id": parent_id,
        }

    def page(
        self, person: Participant, *, after: int = 0, limit: int = 20
    ) -> dict[str, Any]:
        integer(after)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HumanTribuError("invalid_limit")
        person = self.authenticate(person.token)
        people = self._people()
        with self.lock, closing(self._db()) as db, db:
            rows = db.execute(
                "SELECT r.sequence,r.record,r.revision,r.message,m.latest "
                "FROM revisions r JOIN messages m ON m.id=r.message WHERE "
                "m.being=? AND r.sequence>? AND "
                "json_extract(r.record,'$.human.telegram_id')=? "
                "ORDER BY r.sequence LIMIT ?",
                (person.being_ref, after, person.human_id, limit),
            ).fetchall()
            items = []
            for sequence, raw, revision, source_id, latest in rows:
                record = json.loads(raw)
                if record["context"] is None:
                    record["context"] = self._context(
                        db, record["source"]["reply_message_id"], people
                    )
                record.update(
                    sequence=sequence,
                    current_revision=latest,
                    superseded=revision != latest,
                    state="exposed-to-query",
                )
                db.execute(
                    "INSERT OR IGNORE INTO exposures VALUES(?,?,?)",
                    (source_id, revision, self.clock()),
                )
                record["reply_operations"] = [
                    {
                        "id": reply["id"],
                        "state": reply["state"],
                        "confirmed_parts": sum(
                            p["state"] == "confirmed" for p in reply["parts"]
                        ),
                        "part_count": len(reply["parts"]),
                    }
                    for row in db.execute(
                        "SELECT record FROM replies WHERE being=? AND "
                        "source=? AND revision=?",
                        (person.being_ref, source_id, revision),
                    )
                    for reply in [json.loads(row[0])]
                ]
                items.append(record)
            return {
                "schema": "dm.tribu-human-page/v1",
                "items": items,
                "after": after,
                "next": after if not rows else rows[-1][0],
                "state_meaning": "query exposure, not human read or comprehension",
            }

    def parents(
        self, person: Participant, *, after: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        person = self.authenticate(person.token)
        integer(after)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise HumanTribuError("invalid_limit")
        with closing(self._db()) as db:
            rows = db.execute(
                "SELECT id,parent FROM pending WHERE human=? AND resolved=0 "
                "AND id>? ORDER BY id LIMIT ?",
                (person.human_id, after, limit + 1),
            ).fetchall()
        return {
            "items": [
                {"update_id": row[0], "parent_id": row[1]} for row in rows[:limit]
            ],
            "next": after if not rows else rows[:limit][-1][0],
            "has_more": len(rows) > limit,
        }

    def _source(
        self, db: sqlite3.Connection, person: Participant, source_id: str, revision: str
    ) -> dict[str, Any]:
        row = db.execute(
            "SELECT r.record,m.latest FROM messages m JOIN revisions r ON "
            "r.message=m.id AND r.revision=? WHERE m.id=? AND m.being=?",
            (revision, source_id, person.being_ref),
        ).fetchone()
        if row is None or row[1] != revision:
            raise HumanTribuError("source_unavailable_or_changed")
        record: dict[str, Any] = json.loads(row[0])
        if record["human"]["telegram_id"] != person.human_id:
            raise HumanTribuError("source_human_changed")
        if record["eligible"] is not True:
            raise HumanTribuError("source_withdrawn")
        return record

    def _reply_event(
        self, person: Participant, event: dict[str, Any]
    ) -> dict[str, Any]:
        authority = authority_from_document(person.authority)
        verify_event(event, authority)
        member = authority.validate_origin(event["origin"], require_active=True)
        verify_embodiment_credential(
            authority.credentials[member["embodiment_credential_id"]],
            authority.state,
            at_ms=self.clock(),
        )
        if (
            event["origin"] != dict(person.origin)
            or event["being_ref"] != person.being_ref
            or event["kind"] != "experience.observed"
            or event["subject"] != "tribu-human-reply"
            or event["sensitivity"] != "shareable"
            or event["causal_parents"]
        ):
            raise HumanTribuError("reply_author_rejected")
        payload = closed(
            event["payload"], {"schema", "request_id", "source_id", "revision", "text"}
        )
        if (
            payload["schema"] != REPLY_SCHEMA
            or str(uuid.UUID(payload["request_id"])) != payload["request_id"]
        ):
            raise HumanTribuError("reply_invalid")
        if (
            type(payload["text"]) is not str
            or not 0 < len(payload["text"].encode()) <= 65536
        ):
            raise HumanTribuError("reply_text_invalid")
        return payload

    def publication(self, person: Participant, operation: str) -> dict[str, Any]:
        person = self.authenticate(person.token)
        with closing(self._db()) as db:
            row = db.execute(
                "SELECT record FROM replies WHERE id=? AND being=?",
                (operation, person.being_ref),
            ).fetchone()
        if row is None:
            raise HumanTribuError("publication_unavailable")
        return document(row[0].encode())

    def reply(
        self,
        person: Participant,
        event: dict[str, Any],
        exchange: Callable[[dict[str, Any]], bytes],
    ) -> dict[str, Any]:
        person = self.authenticate(person.token)
        payload = self._reply_event(person, event)
        operation = payload["request_id"]
        with closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            source = self._source(db, person, payload["source_id"], payload["revision"])
            previous = db.execute(
                "SELECT hash,record FROM replies WHERE id=?", (operation,)
            ).fetchone()
            if previous is not None:
                if previous[0] != digest(event):
                    raise HumanTribuError("reply_conflict")
            else:
                projection = {
                    "kind": "reply",
                    "sender": person.label,
                    "recipients": [person.human_name],
                    "content": {"text": payload["text"]},
                    "reply_to": {"sender": person.human_name, "text": source["text"]},
                }
                record = {
                    "schema": "dm.tribu-human-publication/v1",
                    "id": operation,
                    "source_id": payload["source_id"],
                    "revision": payload["revision"],
                    "event": event,
                    "state": "prepared",
                    "parts": [
                        {"text": part, "state": "prepared", "response": None}
                        for part in render_readable_parts(projection)
                    ],
                }
                db.execute(
                    "INSERT INTO replies VALUES(?,?,?,?,?,?)",
                    (
                        operation,
                        person.being_ref,
                        digest(event),
                        payload["source_id"],
                        payload["revision"],
                        json_bytes(record).decode(),
                    ),
                )
        while True:
            # One atomic claim per part. No SQLite/Python lock spans network I/O;
            # parallel queries stay available and parallel retries cannot dispatch.
            person = self.authenticate(person.token)
            self._reply_event(person, event)
            with closing(self._db()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                record = document(
                    db.execute("SELECT record FROM replies WHERE id=?", (operation,))
                    .fetchone()[0]
                    .encode()
                )
                if record["state"] != "prepared":
                    return record
                source = self._source(
                    db, person, payload["source_id"], payload["revision"]
                )
                index = next(
                    i for i, p in enumerate(record["parts"]) if p["state"] == "prepared"
                )
                part = record["parts"][index]
                parent = (
                    source["source"]["message_id"]
                    if index == 0
                    else record["parts"][index - 1]["message_id"]
                )
                request = plain_request(
                    part["text"],
                    chat_id=self.chat_id,
                    topic_id=source["source"]["topic_id"],
                    readable=True,
                    reply_message_id=parent,
                )
                request["reply_parameters"]["allow_sending_without_reply"] = False
                part.update(state="sending", request=request)
                record["state"] = "sending"
                db.execute(
                    "UPDATE replies SET record=? WHERE id=?",
                    (json_bytes(record).decode(), operation),
                )
            raw = None
            try:
                raw = exchange(request)
                result = validate_plain_response(
                    raw,
                    request,
                    bot_id=self.bot_id,
                    reply_author_id=person.human_id if index == 0 else None,
                )
                if (
                    result["result"].get("reply_to_message", {}).get("message_id")
                    != parent
                ):
                    raise HumanTribuError("reply_parent_unconfirmed")
                message_id = result["result"]["message_id"]
                part.update(
                    state="confirmed", message_id=message_id, response=raw.decode()
                )
                record["state"] = (
                    "confirmed"
                    if all(p["state"] == "confirmed" for p in record["parts"])
                    else "prepared"
                )
            except Exception:
                part.update(
                    state="uncertain",
                    response=None if raw is None else raw.decode(errors="replace"),
                )
                record["state"] = "uncertain"
            with closing(self._db()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "UPDATE replies SET record=? WHERE id=?",
                    (json_bytes(record).decode(), operation),
                )
                if part["state"] == "confirmed":
                    db.execute(
                        "INSERT INTO posts VALUES(?,?,?,?,?,?)",
                        (
                            message_id,
                            person.being_ref,
                            event["event_id"],
                            event["content_hash"],
                            part["text"],
                            json_bytes(record).decode(),
                        ),
                    )
            if record["state"] != "prepared":
                return record

    def register_post(
        self, person: Participant, event: dict[str, Any], proof: dict[str, Any]
    ) -> dict[str, Any]:
        """Native speech attribution plus full authenticated confirmed echo proof.

        This is not the optional Telegram display-reference cache. Operator
        enrolled verification keys are scoped to one body's real catalogs.
        """
        person = self.authenticate(person.token)
        authority = authority_from_document(person.authority)
        verify_event(event, authority)
        if (
            event["origin"] != dict(person.origin)
            or event["being_ref"] != person.being_ref
        ):
            raise HumanTribuError("post_author_rejected")
        member = authority.validate_origin(event["origin"], require_active=True)
        verify_embodiment_credential(
            authority.credentials[member["embodiment_credential_id"]],
            authority.state,
            at_ms=self.clock(),
        )
        key = person.proof_keys.get(proof.get("catalog_id", ""))
        if key is None:
            raise HumanTribuError("post_catalog_rejected")
        native_json = json.dumps(
            {k: v for k, v in proof.items() if k != "authentication"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        expected = hmac.new(
            key, b"daimon-echo-proof/v2\0" + native_json.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(proof.get("authentication", ""), expected):
            raise HumanTribuError("post_proof_rejected")
        validate_proof_shape(proof)
        if proof["binding_digest"] != digest(proof["binding"]):
            raise HumanTribuError("post_binding_digest_rejected")
        projection, policy = proof["binding"]["projection"], proof["binding"]["policy"]
        if (
            projection["event_id"] != event["event_id"]
            or projection["event_digest"] != event["content_hash"]
            or projection["kind"] not in ("message", "reply")
            or projection["sender"] != person.label
            or policy["bot_id"] != self.bot_id
            or policy["chat_id"] != self.chat_id
        ):
            raise HumanTribuError("post_binding_rejected")
        if (
            event["kind"] != "experience.observed"
            or event["subject"] != "communication"
            or event["payload"].get("schema") != "dm.communication.message/v1"
            or event["payload"].get("body", {}).get("text")
            != projection["content"]["text"]
        ):
            raise HumanTribuError("post_content_rejected")
        with self.lock, closing(self._db()) as db, db:
            ids: list[int] = []
            for index, part in enumerate(proof["parts"]):
                request = _record_request(proof, index)
                attempt = part["attempts"][-1]
                if attempt["response"] is None:
                    raise HumanTribuError("post_unconfirmed")
                result = validate_plain_response(
                    attempt["response"].encode(), request, bot_id=self.bot_id
                )
                message_id = result["result"]["message_id"]
                value = (
                    message_id,
                    person.being_ref,
                    event["event_id"],
                    event["content_hash"],
                    part["text"],
                    json_bytes({"event": event, "proof": proof}).decode(),
                )
                old = db.execute(
                    "SELECT being,event_id,event_hash,text FROM posts WHERE id=?",
                    (message_id,),
                ).fetchone()
                if old is not None and tuple(old) != value[1:5]:
                    raise HumanTribuError("post_conflict")
                db.execute("INSERT OR IGNORE INTO posts VALUES(?,?,?,?,?,?)", value)
                ids.append(message_id)
            unresolved = (
                [
                    document(row[0].encode())
                    for row in db.execute(
                        "SELECT record FROM pending WHERE resolved=0 AND parent IN ("
                        + ",".join("?" for _ in ids)
                        + ") ORDER BY id",
                        ids,
                    )
                ]
                if ids
                else []
            )
        for update in unresolved:
            self.ingest(update)
        return {"registered": ids, "event_id": event["event_id"]}
