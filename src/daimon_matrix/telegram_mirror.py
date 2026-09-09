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
import html
import json
import os
import re
import sqlite3
import stat
import urllib.request
from bisect import bisect_right
from collections.abc import Callable, Iterator
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
