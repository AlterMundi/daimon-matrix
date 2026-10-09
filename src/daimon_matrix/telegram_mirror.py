"""Explicit owner-local native Telegram mirror; disabled unless configured.

Rendering/urllib sending adapted from AlterMundi/tribe-bridge
src/tribe_mirror_v1.py, inspected at b81a6838dd81167f7a8ffcae82cd7ebaadfa21e2;
source last changed 4a99e24292442d4051def9bda539d3a27755e42b (#45), SHA256
cc7c8e6ca367e889b8f047a52a9322e477c284b0b98b0c91a5e9f388afb56851.
The pinned scripts/mirror_v1.py was also reviewed: its whole-message retry
loop is NOT per-part durable progress. This module replaces that state/loop,
not its retired transport. No Tribe imports, envelopes, inbound or migration.
Chunking change author: nicoechaniz <nicoechaniz@altermundi.net> (#45).
No LICENSE file was present at the pinned source root; extraction/release
permission and the repository no-copy/provenance review remain integration gates.

Limits: 64 KiB UTF-8 text, 128 characters per display/correlation field, 32 parts,
4096 retained events; capacity fails closed, never evicts duplicate history.
The owner-only SQLite journal stores hashes and Telegram part IDs, not plaintext
or tokens. It is not tamper/rollback-proof; backup and retention are owner duties.
No background retries, native receipts, all-inbox access or Telegram input exist.

"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import html
import http.client
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from bisect import bisect_right
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, repr=False)
class MirrorMessage:
    """Minimal owner-resolved projection, never a caller-supplied wire message.

    event_digest is the authenticated native event hash; authorization_digest
    binds the current complete native channel decision, not the sharing policy.
    sender/channel are explicitly approved display labels. Every projected field
    (including event/thread correlation) must be approved for external sharing.
    No raw envelopes, private source provenance or arbitrary metadata are accepted.
    """

    event_id: str
    event_digest: str
    authorization_digest: str
    sender: str
    channel: str
    thread_id: str
    text: str


MAX_TEXT_BYTES = 65536
MAX_PARTS = 32
MAX_RECORDS = 4096
_HASH = re.compile(r"[0-9a-f]{64}")


class MirrorOversize(ValueError):
    """Suppressed without emitting any message or metadata."""


def render_parts(message: MirrorMessage) -> list[str]:
    if (
        len(message.text) > MAX_TEXT_BYTES
        or len(message.text.encode("utf-8")) > MAX_TEXT_BYTES
        or any(
            len(v) > 128
            for v in (
                message.sender,
                message.channel,
                message.event_id,
                message.thread_id,
            )
        )
    ):
        raise MirrorOversize("mirror_oversize")
    # Adapted escaped-prefix chunking: never split an HTML entity. Count UTF-16
    # units too, conservatively covering Telegram astral-character accounting.
    text = message.text
    prefix = [0]
    for char in text:
        prefix.append(prefix[-1] + len(html.escape(char).encode("utf-16-le")) // 2)
    chunks, start = [], 0
    while start < len(text):
        end = max(start + 1, bisect_right(prefix, prefix[start] + 3000) - 1)
        chunks.append(text[start:end])
        start = end
    chunks = chunks or [""]
    provenance = (
        f"Daimon Matrix · {message.sender} → {message.channel} · "
        f"{message.event_id} · thread {message.thread_id}"
    )
    total = len(chunks)
    parts = [
        f"<b>{html.escape(provenance)}"
        + (f" · part {i}/{total}" if total > 1 else "")
        + f"</b>\n{html.escape(chunk)}"
        for i, chunk in enumerate(chunks, 1)
    ]
    if len(parts) > MAX_PARTS or any(
        len(p.encode("utf-16-le")) // 2 > 4096 for p in parts
    ):
        raise MirrorOversize("mirror_oversize")
    return parts


@dataclass(frozen=True)
class SharingBinding:
    """Result of an independent, current participant-sharing policy verifier.

    This value is NOT consent proof. Only a trusted owner-installed verifier
    may produce it, after verifying participant approval and its exact scope.
    It must be independent of native transport grants and Telegram membership.
    Policy loading, signatures, freshness and participant enrollment belong to
    the integrating owner; this library does not implement those ceremonies.
    """

    policy_digest: str
    event_digest: str
    authorization_digest: str
    chat_id: int


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any
    ) -> None:
        return None


@contextmanager
def _state(path: str | os.PathLike[str]) -> Iterator[sqlite3.Connection]:
    """Linux owner-local state; ancestors must be trusted and never replaced.

    Never unlink/rotate this database: losing it loses duplicate suppression.
    flock serializes cooperating adapters across the intent/HTTP/commit gap.
    """
    target = Path(path)
    parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("mirror_state_permissions")
        fd = os.open(
            target.name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=parent,
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or info.st_size > 8 * 1024 * 1024
        ):
            raise ValueError("mirror_state_permissions")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(parent)
        with closing(
            sqlite3.connect(f"/proc/self/fd/{parent}/{target.name}", timeout=0)
        ) as db:
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA max_page_count=2048")
            yield db
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


# V2 primitives are intentionally separate: V1 remains selective and is NOT a gate.
def render_plain_parts(document: str) -> list[str]:
    """Complete, unnormalized plaintext; no markup interpretation or truncation."""
    if (
        type(document) is not str
        or not document
        or len(document.encode("utf-8")) > 98304
    ):
        raise ValueError("echo_projection_invalid")
    chunks, chunk, units = [], "", 0
    for char in document:
        size = len(char.encode("utf-16-le")) // 2
        if units + size > 3000:
            chunks.append(chunk)
            chunk, units = "", 0
        chunk += char
        units += size
    chunks.append(chunk)
    if len(chunks) > MAX_PARTS:
        raise ValueError("echo_projection_invalid")
    return [
        f"Daimon Matrix visibility v2 · part {i}/{len(chunks)}\n{c}"
        for i, c in enumerate(chunks, 1)
    ]


PLAIN_REPRESENTATION = "plain-json/v2"
COMPACT_REPRESENTATION = "compact-html/v1"
READABLE_REPRESENTATION = "compact-text/v1"
REPRESENTATIONS = (
    PLAIN_REPRESENTATION,
    COMPACT_REPRESENTATION,
    READABLE_REPRESENTATION,
)

_BEING_REF = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
_SPEECH_KINDS = ("message", "reply")
_FAILED_RECEIPT_OUTCOMES = (
    "failed:transport",
    "refused:policy",
    "expired",
    "resolved:unroutable",
)


def _display_identity(value: str) -> str:
    """Bounded human display for one approved projection identity string.

    Trusted display names pass through untouched. Opaque being refs are
    shortened deterministically (prefix + suffix) so a human can correlate
    them with local records without flooding the channel. Presentation only:
    never derived from message content, never an authority.
    """
    if _BEING_REF.fullmatch(value):
        token = value.removeprefix("dm:being:v1:")
        return f"being:{token[:8]}\u2026{token[-6:]}"
    return value


def _bounded_ref(value: str) -> str:
    return value if len(value) <= 16 else value[:16] + "\u2026"


def _compact_chunks(payload: str) -> list[str]:
    """Escaped-prefix chunking identical in limits to render_plain_parts."""
    if (
        not payload
        or len(payload.encode("utf-8")) > 98304
        or len(payload) > MAX_TEXT_BYTES
    ):
        raise ValueError("echo_projection_invalid")
    prefix = [0]
    for char in payload:
        unit = len(html.escape(char).encode("utf-16-le")) // 2
        prefix.append(prefix[-1] + unit)
    chunks, start = [], 0
    while start < len(payload):
        end = max(start + 1, bisect_right(prefix, prefix[start] + 3000) - 1)
        chunks.append(payload[start:end])
        start = end
    if len(chunks) > MAX_PARTS:
        raise ValueError("echo_projection_invalid")
    return chunks


def render_compact_parts(projection: Mapping[str, Any]) -> list[str]:
    """Human-facing rendering of one validated echo projection.

    Speech renders as ``sender -> recipient`` plus the complete text, chunked
    safely, with a bounded reply reference. Actionable failures render as one
    distinguishable warning line. Successful transport acknowledgments and
    authorization/control chatter render as ZERO parts: suppressed by
    representation, which is recorded honestly in the echo journal and never
    presented as an acknowledged Telegram post.
    """
    kind = projection["kind"]
    sender = _display_identity(projection["sender"])
    recipient = _display_identity(projection["recipients"][0])
    if kind in _SPEECH_KINDS:
        text = projection["content"]["text"]
        if len(text) > MAX_TEXT_BYTES or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError("echo_projection_invalid")
        header = f"Daimon Matrix \u00b7 {sender} \u2192 {recipient}"
        if kind == "reply":
            reply_ref = _bounded_ref(projection["reply_to"]["event_id"])
            header += f" \u00b7 \u21a9 reply to {reply_ref}"
        chunks = _compact_chunks(text) if text else [""]
        total = len(chunks)
        rendered = []
        for index, chunk in enumerate(chunks, 1):
            suffix = f" \u00b7 part {index}/{total}" if total > 1 else ""
            head = html.escape(header + suffix)
            rendered.append(f"<b>{head}</b>\n{html.escape(chunk)}")
        return rendered
    if kind == "semantic-receipt":
        outcome = projection["content"]["outcome"]
        if outcome == "delivered":
            return []
        if outcome not in _FAILED_RECEIPT_OUTCOMES:
            raise ValueError("echo_projection_invalid")
        line = (
            f"\u26a0 Daimon Matrix \u00b7 delivery {outcome} \u00b7 "
            f"{sender} \u2192 {recipient} \u00b7 "
            f"event {_bounded_ref(projection['event_id'])}"
        )
        return [f"<b>{html.escape(line)}</b>"]
    if kind == "transport-result":
        stage = projection["content"]["stage"]
        outcome = projection["content"]["outcome"]
        if outcome == "accepted":
            return []
        line = (
            f"\u26a0 Daimon Matrix \u00b7 transport refused ({stage}) \u00b7 "
            f"{sender} \u2192 {recipient} \u00b7 "
            f"event {_bounded_ref(projection['event_id'])}"
        )
        return [f"<b>{html.escape(line)}</b>"]
    if kind == "authorization-control":
        return []
    raise ValueError("echo_projection_invalid")


def render_echo_parts(projection: Mapping[str, Any], representation: str) -> list[str]:
    """Dispatch one validated projection through its policy representation.

    Pure function of (projection, representation): the echo journal re-renders
    it from the authenticated binding when validating proofs, so a record
    admitted under one representation always re-derives byte-identically.
    """
    if representation == PLAIN_REPRESENTATION:
        return render_plain_parts(
            json.dumps(dict(projection), ensure_ascii=False, sort_keys=True, indent=2)
        )
    if representation == COMPACT_REPRESENTATION:
        return render_compact_parts(projection)
    if representation == READABLE_REPRESENTATION:
        return render_readable_parts(projection)
    raise ValueError("echo_representation_unknown")


def _readable_identity(value: str) -> str:
    """Format producer-resolved metadata, never text written by the speaker."""
    display = _display_identity(value)
    if display.startswith("being:"):
        return "Daimon sin nombre · " + display.removeprefix("being:")
    if re.fullmatch(r"[a-z0-9-]+\.[a-z0-9-]+@[a-z0-9.-]+", value):
        name, body = value.split(".", 1)
        name = "CompAII" if name == "compaii" else name.capitalize()
        return f"{name} · {body}"
    if value == "compaii":
        return "CompAII"
    return value.capitalize() if value in {"eko", "oliva"} else display


def _readable_chunks(text: str, *, budget: int, paragraphs: bool = True) -> list[str]:
    """Prefer paragraph/line boundaries, preserving every original character."""
    if not text or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError("echo_projection_invalid")
    chunks = []
    while text:
        units, end = 0, 0
        for char in text:
            size = len(char.encode("utf-16-le")) // 2
            if units + size > budget:
                break
            units += size
            end += 1
        if paragraphs and end < len(text):
            boundary = text.rfind("\n", 0, end)
            if boundary >= end // 2:
                end = boundary + 1
        chunks.append(text[:end])
        text = text[end:]
    if len(chunks) > MAX_PARTS:
        if paragraphs:
            return _readable_chunks("".join(chunks), budget=budget, paragraphs=False)
        raise ValueError("echo_projection_invalid")
    return chunks


def render_readable_parts(projection: Mapping[str, Any]) -> list[str]:
    """Successor plaintext presentation; old representations stay byte-exact."""
    kind = projection["kind"]
    sender = _readable_identity(projection["sender"])
    recipient = _readable_identity(projection["recipients"][0])
    route = f"{sender} → {recipient}"
    if kind in _SPEECH_KINDS:
        context = ""
        if kind == "reply":
            parent = projection["reply_to"]
            if "sender" in parent and "text" in parent:
                excerpt = parent["text"][:160].replace("\n", " ")
                if len(parent["text"]) > 160:
                    excerpt += "…"
                context = f"↩ {_readable_identity(parent['sender'])}: «{excerpt}»\n"
            else:
                context = "↩ Respuesta a un mensaje anterior\n"
            if "receipt" in parent:
                context += "✓ Entrega del mensaje anterior confirmada\n"
        overhead = len((route + "\n" + context + "\n").encode("utf-16-le")) // 2
        chunks = _readable_chunks(
            projection["content"]["text"], budget=4096 - overhead - 24
        )
        return [
            route
            + (f" · {index}/{len(chunks)}" if len(chunks) > 1 else "")
            + "\n"
            + context
            + "\n"
            + chunk
            for index, chunk in enumerate(chunks, 1)
        ]
    if kind == "semantic-receipt":
        outcome = projection["content"]["outcome"]
        descriptions = {
            "delivered": "✓ Entrega confirmada",
            "failed:transport": "⚠ Falló la entrega",
            "refused:policy": "⚠ Entrega rechazada por la política vigente",
            "expired": "⚠ El envío venció sin entrega confirmada",
            "resolved:unroutable": "⚠ No hay una ruta disponible",
        }
        if outcome not in descriptions:
            raise ValueError("echo_projection_invalid")
        return [descriptions[outcome] + "\n" + route]
    if kind == "transport-result":
        if projection["content"]["outcome"] == "accepted":
            return []
        return ["⚠ El transporte rechazó el envío\n" + route]
    if kind == "authorization-control":
        return []
    raise ValueError("echo_projection_invalid")


def plain_request(
    text: str,
    *,
    chat_id: int,
    topic_id: int | None,
    readable: bool = False,
    reply_message_id: int | None = None,
) -> dict[str, Any]:
    if (
        type(chat_id) is not int
        or not 0 < abs(chat_id) < 2**52
        or (
            topic_id is not None
            and (type(topic_id) is not int or not 0 < topic_id < 2**31)
        )
        or type(text) is not str
        or not text
        or len(text.encode("utf-16-le")) // 2 > 4096
    ):
        raise ValueError("echo_request_invalid")
    value: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "link_preview_options": {"is_disabled": True},
    }
    if topic_id is not None:
        value["message_thread_id"] = topic_id
    if readable:
        value["entities"] = [
            {
                "type": "bold",
                "offset": 0,
                "length": len(text.split("\n", 1)[0].encode("utf-16-le")) // 2,
            }
        ]
    if reply_message_id is not None:
        if (
            not readable
            or type(reply_message_id) is not int
            or not 0 < reply_message_id < 2**52
        ):
            raise ValueError("echo_request_invalid")
        value["reply_parameters"] = {
            "message_id": reply_message_id,
            "allow_sending_without_reply": True,
        }
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def validate_plain_response(
    raw: bytes, request: dict[str, Any], *, bot_id: int
) -> dict[str, Any]:
    """Validate literal text and bot/chat/topic pins in retained Bot API evidence.

    Telegram can remove terminal LF characters from a successful text response.
    Preserve the frozen request and actual response; accept only that observed
    boundary normalization, never interior changes or other truncation.
    An ordinary supergroup reply's derived thread must be proven by its exact
    returned requested parent; an explicitly selected forum topic remains pinned.
    """
    try:
        if type(raw) is not bytes or len(raw) > 65536:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        result = value["result"]
        topic = request.get("message_thread_id")
        if type(bot_id) is not int or not 0 < bot_id < 2**52:
            raise ValueError
        if topic is None:
            if result.get("is_topic_message", False) is not False:
                raise ValueError
        elif (
            type(result.get("message_thread_id")) is not int
            or result.get("is_topic_message") is not True
        ):
            raise ValueError
        entities = result.get("entities", [])
        if type(entities) is not list or len(entities) > 4096:
            raise ValueError
        expected_entities = request.get("entities", [])
        found_entities = []
        for entity in entities:
            if (
                type(entity) is not dict
                or set(entity) != {"type", "offset", "length"}
                or entity["type"]
                not in {
                    "mention",
                    "hashtag",
                    "cashtag",
                    "bot_command",
                    "url",
                    "email",
                    "phone_number",
                    "bold",
                }
                or type(entity["offset"]) is not int
                or entity["offset"] < 0
                or type(entity["length"]) is not int
                or entity["length"] <= 0
                or entity["offset"] + entity["length"]
                > len(request["text"].encode("utf-16-le")) // 2
            ):
                raise ValueError
            if entity["type"] == "bold":
                if entity not in expected_entities or entity in found_entities:
                    raise ValueError
                found_entities.append(entity)
        if found_entities != expected_entities:
            raise ValueError
        parent = result.get("reply_to_message")
        if parent is not None:
            expected_reply = request.get("reply_parameters", {}).get("message_id")
            if (
                type(parent) is not dict
                or type(parent.get("message_id")) is not int
                or parent["message_id"] != expected_reply
                or type(parent.get("chat", {}).get("id")) is not int
                or parent.get("chat", {}).get("id") != request["chat_id"]
                or type(parent.get("from", {}).get("id")) is not int
                or parent.get("from", {}).get("id") != bot_id
                or parent.get("from", {}).get("is_bot") is not True
                or (topic is not None and parent.get("message_thread_id") != topic)
                or (topic is not None and parent.get("is_topic_message") is not True)
                or (
                    topic is None and parent.get("is_topic_message", False) is not False
                )
            ):
                raise ValueError
        returned_thread = result.get("message_thread_id")
        if topic is None and "message_thread_id" in result and returned_thread is None:
            raise ValueError
        if topic is None and returned_thread is not None:
            # Ordinary supergroup replies also have a thread root. This is
            # platform evidence of the exact requested parent, not a forum topic.
            if (
                type(returned_thread) is not int
                or not 0 < returned_thread < 2**52
                or result["chat"].get("type") != "supergroup"
                or parent is None
                or parent["chat"].get("type") != "supergroup"
            ):
                raise ValueError
            root = parent.get("message_thread_id", parent["message_id"])
            if type(root) is not int or not 0 < root < 2**52 or returned_thread != root:
                raise ValueError
        elif returned_thread != topic:
            raise ValueError
        if topic is None and parent is not None:
            parent_thread = parent.get("message_thread_id")
            if parent_thread is not None and (
                type(parent_thread) is not int
                or not 0 < parent_thread < 2**52
                or returned_thread != parent_thread
            ):
                raise ValueError
        if (
            value.get("ok") is not True
            or type(result["message_id"]) is not int
            or not 0 < result["message_id"] < 2**52
            or type(result["chat"]["id"]) is not int
            or result["chat"]["id"] != request["chat_id"]
            or type(result["from"]["id"]) is not int
            or result["from"]["id"] != bot_id
            or result["from"].get("is_bot") is not True
            or result.get("text") not in (request["text"], request["text"].rstrip("\n"))
        ):
            raise ValueError
        return dict(value)
    except Exception:
        raise ValueError("echo_response_invalid") from None


def classify_plain_response(
    raw: bytes, request: dict[str, Any], *, bot_id: int
) -> tuple[str, int]:
    """Platform acceptance or explicit Bot API rejection; never infer from timeout.

    Unknown/malformed/5xx results are ambiguous. A valid negative response retains
    its full evidence but cannot satisfy confirmation. Retry delay is bounded.
    """
    try:
        if type(raw) is not bytes or len(raw) > 65536:
            raise ValueError
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if value.get("ok") is True:
            validate_plain_response(raw, request, bot_id=bot_id)
            return "confirmed", 0
        if (
            type(value) is not dict
            or set(value)
            not in (
                {"ok", "error_code", "description"},
                {"ok", "error_code", "description", "parameters"},
            )
            or value["ok"] is not False
            or type(value["error_code"]) is not int
            or value["error_code"] not in (400, 401, 403, 404, 409, 429)
            or type(value["description"]) is not str
            or not 0 < len(value["description"]) <= 4096
        ):
            raise ValueError
        delay = 30
        if "parameters" in value:
            parameters = value["parameters"]
            if type(parameters) is not dict or set(parameters) != {"retry_after"}:
                raise ValueError
            delay = parameters["retry_after"]
            if type(delay) is not int or not 1 <= delay <= 86400:
                raise ValueError
        return "rejected", delay
    except Exception:
        raise ValueError("echo_response_invalid") from None


_PLAIN_HTTP_SECONDS = 10.0


def _plain_lifetime_mode() -> str:
    platform_name = sys.platform
    if platform_name == "linux":
        return "linux"
    if platform_name == "darwin":
        return "terminal"
    raise ValueError("echo_executor_platform_unsupported")


@contextmanager
def _plain_lifetime() -> Iterator[int | None]:
    """Own the Darwin executor's terminal master until the executor is reaped.

    No terminal carries request bytes or secrets. Fresh exec, not pty.fork or a
    Python preexec_fn, isolates macOS system-library state before urllib runs.
    No unrelated child may inherit the master: both descriptors are CLOEXEC,
    and the executor receives only the slave in its explicit pass_fds set.
    """
    if _plain_lifetime_mode() == "linux":
        yield None
        return
    master, slave = os.openpty()
    try:
        os.set_inheritable(master, False)
        os.set_inheritable(slave, False)
        yield slave
    finally:
        os.close(slave)
        os.close(master)


def _plain_http_exchange(url: str, payload: bytes) -> tuple[int, bytes]:
    """One isolated local executor, killed/reaped on EVERY interrupted exit.

    The monotonic budget includes interpreter startup, DNS, connect/TLS, HTTP
    headers/framing/body and IPC. Never release a caller's guard with a live
    executor. Reaping may take OS scheduling time; remote cancellation is NOT
    implied. No token in argv, environment, stderr or an on-disk job file.
    """
    deadline = time.monotonic() + _PLAIN_HTTP_SECONDS
    with (
        _plain_lifetime() as lifetime_fd,
        subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve())],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            pass_fds=() if lifetime_fd is None else (lifetime_fd,),
            env={},
        ) as child,
    ):
        try:
            data = json.dumps(
                [os.getpid(), url, payload.decode("utf-8"), lifetime_fd]
            ).encode()
            output, _ = child.communicate(
                data, timeout=max(0, deadline - time.monotonic())
            )
            if child.returncode != 0 or time.monotonic() >= deadline:
                raise ValueError
            status, raw = output.split(b"\n", 1)
            if len(status) != 3 or len(raw) > 65536:
                raise ValueError
            return int(status), raw
        finally:
            # Includes KeyboardInterrupt/SystemExit and unexpected IPC failures.
            # kill + wait, not an abandoned thread/future or a daemon task.
            if child.poll() is None:
                child.kill()
            child.wait()


class _PlainBoundedReader:
    """Bound cumulative raw HTTP bytes, including headers/chunks/trailers."""

    def __init__(self, reader: Any) -> None:
        self._reader = reader
        self._remaining = 262144

    def _read(self, size: int, *, line: bool) -> bytes:
        limit = self._remaining + 1
        size = limit if size < 0 else min(size, limit)
        raw = self._reader.readline(size) if line else self._reader.read(size)
        self._remaining -= len(raw)
        if self._remaining < 0:
            raise ValueError("echo_http_framing_limit")
        return bytes(raw)

    def read(self, size: int = -1) -> bytes:
        return self._read(size, line=False)

    def readline(self, size: int = -1) -> bytes:
        return self._read(size, line=True)

    def close(self) -> None:
        self._reader.close()


class _PlainBoundedResponse(http.client.HTTPResponse):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.fp = _PlainBoundedReader(self.fp)  # type: ignore[assignment]


def _plain_http_child() -> None:
    """Private stdlib-only executor entry; no runtime, journal or lock handles."""
    try:
        # These process-local bounds cannot change the V1 transport in the parent.
        http.client.HTTPConnection.response_class = _PlainBoundedResponse
        http.client.HTTPSConnection.response_class = _PlainBoundedResponse
        data = sys.stdin.buffer.read(131073)
        if len(data) > 131072:
            raise ValueError
        parent_pid, url, payload, lifetime_fd = json.loads(data)
        import signal

        if lifetime_fd is None:
            if sys.platform != "linux":
                raise ValueError
            import ctypes

            if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                raise ValueError
        else:
            # On Darwin the private terminal's master belongs only to the
            # parent. Master closure causes kernel hangup of this foreground
            # session. The same path is exercised with real PTYs on Linux.
            # Never inherit an ignored/blocked HUP disposition from the host.
            import termios

            if (
                sys.platform not in {"darwin", "linux"}
                or type(lifetime_fd) is not int
                or lifetime_fd < 3
                or not os.isatty(lifetime_fd)
            ):
                raise ValueError
            signal.signal(signal.SIGHUP, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGHUP})
            os.setsid()
            fcntl.ioctl(lifetime_fd, termios.TIOCSCTTY, 0)
            if os.tcgetpgrp(lifetime_fd) != os.getpgrp():
                raise ValueError
        # Check AFTER attaching death coupling to close the startup/death race.
        if type(parent_pid) is not int or os.getppid() != parent_pid:
            raise ValueError
        wire = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )
        try:
            response = opener.open(wire, timeout=10)
        except urllib.error.HTTPError as negative:
            response = negative
        with response:
            status = response.status
            raw = response.read(65537)
            if len(raw) > 65536 or getattr(response, "length", None) not in (None, 0):
                raise ValueError
        sys.stdout.buffer.write(str(status).encode() + b"\n" + raw)
        sys.stdout.buffer.flush()
    except Exception:
        # No exception URL, credential, body or traceback crosses this boundary.
        raise SystemExit(1) from None


class PlainTelegramTransport:
    """V2 runtime-only transport. No network on construction, retry or redirects.

    Credential availability/getMe enrollment is the composing runtime's duty.
    A send failure always has an ambiguous outcome; it is never a retry grant.
    """

    def __init__(
        self,
        *,
        token: str,
        bot_id: int,
        chat_id: int,
        topic_id: int | None,
        reference_directory: Path | None = None,
    ) -> None:
        if (
            type(token) is not str
            or not re.fullmatch(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}", token)
            or type(bot_id) is not int
            or not 0 < bot_id < 2**52
            or int(token.split(":", 1)[0]) != bot_id
        ):
            raise ValueError("echo_transport_config_invalid")
        plain_request("validate", chat_id=chat_id, topic_id=topic_id)
        self._token, self._bot_id = token, bot_id
        self._chat_id, self._topic_id = chat_id, topic_id
        self._reference_directory = reference_directory

    def _reference_name(self, event: Mapping[str, Any]) -> str:
        identity = [
            self._bot_id,
            self._chat_id,
            self._topic_id,
            event["event_id"],
            event["event_digest"],
        ]
        return hashlib.sha256(json.dumps(identity).encode()).hexdigest() + ".json"

    def _reference_mac(self, body: Mapping[str, Any]) -> str:
        raw = json.dumps(
            dict(body), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        return hmac.new(
            self._token.encode(), b"dm.telegram.reference/v1\0" + raw, hashlib.sha256
        ).hexdigest()

    def lookup_reference(self, event: Mapping[str, Any]) -> dict[str, Any] | None:
        """Optional fixed-audience correlation cache, never delivery authority.

        Writers are the approved custodians of the same Telegram bot. The MAC
        protects this shared presentation cache; it does not authenticate Matrix
        events or replace their individual native proofs. A miss is harmless.
        """
        if self._reference_directory is None:
            return None
        fd = None
        try:
            fd = os.open(
                self._reference_directory / self._reference_name(event),
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > 4096
            ):
                return None
            value = json.loads(os.read(fd, 4097), object_pairs_hook=_unique_object)
            body = value["body"]
            if (
                set(value) != {"body", "mac"}
                or set(body)
                != {
                    "bot_id",
                    "chat_id",
                    "topic_id",
                    "event_id",
                    "event_digest",
                    "message_id",
                }
                or not hmac.compare_digest(value["mac"], self._reference_mac(body))
                or type(body["bot_id"]) is not int
                or type(body["chat_id"]) is not int
                or (body["topic_id"] is not None and type(body["topic_id"]) is not int)
                or body["bot_id"] != self._bot_id
                or body["chat_id"] != self._chat_id
                or body["topic_id"] != self._topic_id
                or body["event_id"] != event["event_id"]
                or body["event_digest"] != event["event_digest"]
                or type(body["message_id"]) is not int
                or not 0 < body["message_id"] < 2**52
            ):
                return None
            return {
                key: body[key] for key in ("event_id", "event_digest", "message_id")
            }
        except (OSError, ValueError, KeyError, TypeError):
            return None
        finally:
            if fd is not None:
                os.close(fd)

    def publish_reference(self, record: Mapping[str, Any]) -> None:
        """Called only after authenticated journal confirmation of ALL parts."""
        if self._reference_directory is None:
            return
        projection = record["binding"]["projection"]
        if projection["kind"] not in _SPEECH_KINDS:
            return
        if self.lookup_reference(projection) is not None:
            return  # Preserve the first confirmed post under an exact logical ID.
        response = json.loads(record["parts"][0]["attempts"][-1]["response"])
        body = {
            "bot_id": self._bot_id,
            "chat_id": self._chat_id,
            "topic_id": self._topic_id,
            "event_id": projection["event_id"],
            "event_digest": projection["event_digest"],
            "message_id": response["result"]["message_id"],
        }
        raw = json.dumps(
            {"body": body, "mac": self._reference_mac(body)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        fd = None
        try:
            fd = os.open(
                self._reference_directory / self._reference_name(projection),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o644,
            )
            # Correlation metadata is explicitly shared; service umasks must
            # still keep private native proofs and credentials owner-only.
            os.fchmod(fd, 0o644)
            while raw:
                raw = raw[os.write(fd, raw) :]
            os.fsync(fd)
            directory_fd = os.open(
                self._reference_directory, os.O_RDONLY | os.O_DIRECTORY
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass  # Optional correlation cannot discharge or block native proof.
        finally:
            if fd is not None:
                os.close(fd)

    def send(self, request: dict[str, Any]) -> bytes:
        try:
            # Snapshot input once; Python equality alone aliases True and 1.
            serialized = json.dumps(request, sort_keys=True, allow_nan=False)
            request = json.loads(serialized)
            expected = plain_request(
                request["text"],
                chat_id=self._chat_id,
                topic_id=self._topic_id,
                readable="entities" in request,
                reply_message_id=request.get("reply_parameters", {}).get("message_id"),
            )
            if serialized != json.dumps(expected, sort_keys=True, allow_nan=False):
                raise ValueError
        except Exception:
            raise ValueError("echo_request_invalid") from None
        try:
            status, raw = _plain_http_exchange(
                f"https://api.telegram.org/bot{self._token}/sendMessage",
                json.dumps(request, ensure_ascii=False, allow_nan=False).encode(),
            )
            verdict, _ = classify_plain_response(raw, request, bot_id=self._bot_id)
            expected_status = (
                200 if verdict == "confirmed" else json.loads(raw)["error_code"]
            )
            if status != expected_status:
                raise ValueError
            return bytes(raw)
        except Exception:
            raise ValueError("echo_transport_ambiguous") from None


def qualify_telegram_destination(
    *,
    token: str,
    bot_id: int,
    chat_id: int,
    topic_id: int | None,
    probe_text: str,
) -> dict[str, Any]:
    """Explicit owner-ceremony bot/destination qualification.

    ``probe_text`` must be a fresh, unique value supplied by the owner caller.
    The operation performs exactly one getMe and, only after identity matches,
    one sendMessage through the same bounded no-proxy/no-redirect HTTP boundary
    as :class:`PlainTelegramTransport`. It retains only hashes and numeric pins.
    No network occurs merely by importing this module or constructing a
    transport; a future owner CLI must invoke this function explicitly.
    """
    try:
        # Construction validates token syntax, the numeric token prefix, policy
        # bot identity, and destination without performing network I/O.
        transport = PlainTelegramTransport(
            token=token,
            bot_id=bot_id,
            chat_id=chat_id,
            topic_id=topic_id,
        )
        request = plain_request(probe_text, chat_id=chat_id, topic_id=topic_id)

        status, get_me_raw = _plain_http_exchange(
            f"https://api.telegram.org/bot{token}/getMe", b"{}"
        )
        if status != 200 or type(get_me_raw) is not bytes or len(get_me_raw) > 65536:
            raise ValueError
        get_me = json.loads(
            get_me_raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        if type(get_me) is not dict or set(get_me) != {"ok", "result"}:
            raise ValueError
        identity = get_me["result"]
        if (
            get_me["ok"] is not True
            or type(identity) is not dict
            or type(identity.get("id")) is not int
            or identity["id"] != bot_id
            or identity.get("is_bot") is not True
        ):
            raise ValueError

        # send() re-snapshots and validates the exact request and validates the
        # full response (text, sender, chat, topic semantics, and message ID).
        probe_raw = transport.send(request)
        probe_result = validate_plain_response(probe_raw, request, bot_id=bot_id)[
            "result"
        ]
        message_id = probe_result["message_id"]
        qualified_at_ms = time.time_ns() // 1_000_000
        if (
            type(qualified_at_ms) is not int
            or not 0 < qualified_at_ms < 2**63
            or type(message_id) is not int
            or not 0 < message_id < 2**52
        ):
            raise ValueError
        return {
            "schema": "dm.messaging.telegram-qualification/v1",
            "qualified_at_ms": qualified_at_ms,
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "get_me_bot_id": bot_id,
            "probe_chat_id": chat_id,
            "probe_topic_id": topic_id,
            "probe_message_id": message_id,
            "probe_text_sha256": hashlib.sha256(probe_text.encode("utf-8")).hexdigest(),
        }
    except Exception:
        # Never expose token-bearing URLs, raw responses, or upstream details.
        raise ValueError("telegram_qualification_failed") from None


class TelegramMirror:
    """Separate explicit operation, never an intake hook or inbox enumerator.

    resolver(event_id) must freshly authenticate that exact native message and
    recheck current channel authorization, then return only MirrorMessage.
    verify_sharing(message, fixed_chat_id, pinned_policy_digest) must independently
    verify current participant sharing approval and return SharingBinding.
    Both are trusted owner-local callables, not model-facing configuration.
    The verifier must exclude secrets/private traffic and reject reflected
    Telegram-origin events; this module has no heuristic secret detector.
    Revocation freshness depends on these callables; no library can retract an
    already accepted remote part or atomically fence external policy changes.
    state_path must be a dedicated database in an existing owner-only directory
    beneath trusted ancestors; do not point it at native or retired state.

    """

    def __init__(
        self,
        *,
        resolver: Callable[[str], MirrorMessage],
        verify_sharing: Callable[[MirrorMessage, int, str], SharingBinding | None],
        enabled: bool = False,
        token: str = "",
        chat_id: int = 0,
        policy_digest: str = "",
        state_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self._resolver = resolver
        self._verify_sharing = verify_sharing
        self._enabled = enabled
        self._token = token
        self._chat_id = chat_id
        self._policy_digest = policy_digest
        self._state_path = state_path

    def _send(self, rendered: str) -> int:
        # Adapted reviewed urllib sender. No redirects/proxy-environment routing;
        # never propagate raw URL-bearing exceptions or Telegram response bodies.
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{self._token}/sendMessage",
            data=json.dumps(
                {
                    "chat_id": self._chat_id,
                    "text": rendered,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )
        with opener.open(request, timeout=10) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("mirror_response_invalid")
        value = json.loads(raw)
        if type(value) is not dict or value.get("ok") is not True:
            raise ValueError("mirror_response_invalid")
        result = value.get("result")
        if (
            type(result) is not dict
            or type(result.get("message_id")) is not int
            or not 0 < result["message_id"] < 2**52
            or type(result.get("chat")) is not dict
            or type(result["chat"].get("id")) is not int
            or result["chat"]["id"] != self._chat_id
        ):
            raise ValueError("mirror_response_invalid")
        return int(result["message_id"])

    def _resolve(self, event_id: str) -> MirrorMessage | None:
        try:
            message = self._resolver(event_id)
            if type(message) is not MirrorMessage or message.event_id != event_id:
                return None
            if (
                any(type(v) is not str for v in asdict(message).values())
                or not _HASH.fullmatch(message.event_digest)
                or not _HASH.fullmatch(message.authorization_digest)
            ):
                return None
            proof = self._verify_sharing(message, self._chat_id, self._policy_digest)
            expected = SharingBinding(
                self._policy_digest,
                message.event_digest,
                message.authorization_digest,
                self._chat_id,
            )
            if type(proof) is not SharingBinding or proof != expected:
                return None
            return message
        except Exception:
            # Trusted resolver/verifier may carry private source details in errors.
            return None

    def mirror_selected(self, event_id: str) -> dict[str, Any]:
        """Manual retry may duplicate an ambiguous part; never exactly-once.

        Only delivered-to-platform confirms Telegram API acceptance, not human
        reading, native adoption or a signed native receipt. Operational errors
        are sanitized; no native intake state is touched.
        """
        try:
            return self._mirror_selected(event_id)
        except BlockingIOError:
            return {"status": "busy"}
        except Exception:
            return {"status": "unavailable", "ambiguous": True}

    def _mirror_selected(self, event_id: str) -> dict[str, Any]:
        if self._enabled is False:
            return {"status": "disabled"}
        if (
            self._enabled is not True
            or type(self._chat_id) is not int
            or self._chat_id == 0
            or abs(self._chat_id) >= 2**52
            or type(self._token) is not str
            or not re.fullmatch(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}", self._token)
            or type(self._policy_digest) is not str
            or not _HASH.fullmatch(self._policy_digest)
            or not isinstance(self._state_path, (str, os.PathLike))
            or type(event_id) is not str
            or not 0 < len(event_id) <= 128
        ):
            return {"status": "rejected"}
        message = self._resolve(event_id)
        if message is None:
            return {"status": "rejected"}
        try:
            parts = render_parts(message)
        except MirrorOversize:
            return {"status": "suppressed"}
        except (ValueError, TypeError):
            return {"status": "rejected"}
        binding = _digest([asdict(message), self._chat_id, self._policy_digest, parts])
        with _state(self._state_path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS mirror_progress "
                "(event_key TEXT PRIMARY KEY, binding TEXT NOT NULL, "
                "progress TEXT NOT NULL)"
            )
            key = _digest(event_id)
            row = db.execute(
                "SELECT binding,progress FROM mirror_progress WHERE event_key=?", (key,)
            ).fetchone()
            if (
                not row
                and db.execute("SELECT count(*) FROM mirror_progress").fetchone()[0]
                >= MAX_RECORDS
            ):
                return {"status": "capacity"}
            if row and row[0] != binding:
                return {"status": "conflict"}
            progress: list[Any] = json.loads(row[1]) if row else [None] * len(parts)
            if (
                type(progress) is not list
                or len(progress) != len(parts)
                or any(
                    not (
                        p is None
                        or p == "pending"
                        or (type(p) is int and 0 < p < 2**52)
                    )
                    for p in progress
                )
            ):
                raise ValueError("mirror_state_invalid")
            for index, part in enumerate(parts):
                if type(progress[index]) is int:
                    continue
                if self._resolve(event_id) != message:
                    return {"status": "rejected"}
                progress[index] = "pending"
                db.execute(
                    "INSERT OR REPLACE INTO mirror_progress VALUES (?,?,?)",
                    (key, binding, json.dumps(progress)),
                )
                db.commit()  # durable intent BEFORE non-transactional remote I/O
                try:
                    receipt = self._send(part)
                except Exception:
                    return {
                        "status": "pending",
                        "ambiguous": True,
                        "confirmed_parts": sum(type(p) is int for p in progress),
                    }
                progress[index] = receipt
                db.execute(
                    "INSERT OR REPLACE INTO mirror_progress VALUES (?,?,?)",
                    (key, binding, json.dumps(progress)),
                )
                db.commit()
        return {"status": "delivered-to-platform", "confirmed_parts": len(parts)}


if __name__ == "__main__":
    _plain_http_child()
