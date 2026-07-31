from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from . import PROTOCOL


class SpikeError(RuntimeError):
    """A validation or operation error in the experimental protocol."""


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_key_text(key: Ed25519PublicKey) -> str:
    return _b64(key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def public_key_id(public_text: str) -> str:
    return hashlib.sha256(_unb64(public_text)).hexdigest()[:16]


def state_config_path(state_dir: Path) -> Path:
    return state_dir / "config.json"


def load_config(state_dir: Path) -> dict[str, Any]:
    path = state_config_path(state_dir)
    if not path.is_file():
        raise SpikeError(f"experimental state is not initialized: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("protocol") != PROTOCOL:
        raise SpikeError(f"unsupported config protocol in {path}")
    return data


def write_config(state_dir: Path, config: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = state_config_path(state_dir)
    fd, tmp_name = tempfile.mkstemp(prefix="config.", dir=state_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def init_state(
    state_dir: Path,
    *,
    me_id: str,
    incarnation_id: str,
    host: str,
    harness: str,
    hmk_wrapper: str | None = None,
    hmk_base: str | None = None,
    hermes_home: str | None = None,
) -> dict[str, Any]:
    if state_config_path(state_dir).exists():
        raise SpikeError(f"refusing to overwrite initialized state: {state_dir}")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state_dir, 0o700)

    private_key = Ed25519PrivateKey.generate()
    private_path = state_dir / "incarnation.ed25519"
    private_path.write_bytes(
        private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    os.chmod(private_path, 0o600)
    public_text = public_key_text(private_key.public_key())
    config: dict[str, Any] = {
        "protocol": PROTOCOL,
        "experimental": True,
        "me_id": me_id,
        "incarnation_id": incarnation_id,
        "embodiment": {"host": host, "harness": harness},
        "public_key": public_text,
        "key_id": public_key_id(public_text),
        "trusted_incarnations": {incarnation_id: public_text},
        "peers": {},
        "hmk": {
            "wrapper": hmk_wrapper or "",
            "base": hmk_base or "",
            "hermes_home": hermes_home or "",
            "shelf": "episodes",
        },
    }
    write_config(state_dir, config)
    Ledger(state_dir).initialize()
    return config


def trust_incarnation(
    state_dir: Path,
    *,
    incarnation_id: str,
    public_key: str,
    peer_id: str | None = None,
    ssh_host: str | None = None,
    remote_python: str | None = None,
    remote_state_dir: str | None = None,
) -> dict[str, Any]:
    Ed25519PublicKey.from_public_bytes(_unb64(public_key))
    config = load_config(state_dir)
    config.setdefault("trusted_incarnations", {})[incarnation_id] = public_key
    if peer_id:
        required = {
            "ssh_host": ssh_host,
            "remote_python": remote_python,
            "remote_state_dir": remote_state_dir,
        }
        if not all(required.values()):
            raise SpikeError("peer transport requires ssh host, Python, and state dir")
        config.setdefault("peers", {})[peer_id] = {
            "incarnation_id": incarnation_id,
            **required,
        }
    write_config(state_dir, config)
    return config


def _private_key(state_dir: Path) -> Ed25519PrivateKey:
    path = state_dir / "incarnation.ed25519"
    if not path.is_file():
        raise SpikeError(f"missing incarnation private key: {path}")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise SpikeError(f"private key permissions are too broad: {oct(mode)}")
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def event_core(
    config: dict[str, Any],
    *,
    event_id: str,
    sequence: int,
    previous_event_id: str | None,
    title: str,
    content: str,
    tags: list[str],
) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL,
        "event_id": event_id,
        "me_id": config["me_id"],
        "origin_incarnation": config["incarnation_id"],
        "origin_embodiment": config["embodiment"],
        "sequence": sequence,
        "occurred_at": utc_now(),
        "causal_parents": [previous_event_id] if previous_event_id else [],
        "event_type": "memory.lived_experience",
        "payload": {"title": title, "content": content, "tags": tags},
        "signing_key_id": config["key_id"],
    }


def sign_event(state_dir: Path, core: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_bytes(core)).hexdigest()
    private_key = _private_key(state_dir)
    actual_key_id = public_key_id(public_key_text(private_key.public_key()))
    if actual_key_id != core["signing_key_id"]:
        raise SpikeError("incarnation private key does not match config")
    signature = private_key.sign(bytes.fromhex(digest))
    return {**core, "content_hash": digest, "signature": _b64(signature)}


def validate_event(event: dict[str, Any], config: dict[str, Any]) -> None:
    required = {
        "protocol",
        "event_id",
        "me_id",
        "origin_incarnation",
        "origin_embodiment",
        "sequence",
        "occurred_at",
        "causal_parents",
        "event_type",
        "payload",
        "signing_key_id",
        "content_hash",
        "signature",
    }
    if set(event) != required:
        raise SpikeError("event fields do not match the experimental schema")
    if event["protocol"] != PROTOCOL:
        raise SpikeError("event protocol mismatch")
    if event["me_id"] != config["me_id"]:
        raise SpikeError("event belongs to a different /me")
    try:
        uuid.UUID(event["event_id"])
    except (TypeError, ValueError) as exc:
        raise SpikeError("event ID must be a UUID") from exc
    if not isinstance(event["sequence"], int) or event["sequence"] < 1:
        raise SpikeError("event sequence must be a positive integer")
    if event["event_type"] != "memory.lived_experience":
        raise SpikeError("unsupported experimental event type")
    payload = event["payload"]
    if not isinstance(payload, dict) or set(payload) != {"title", "content", "tags"}:
        raise SpikeError("invalid lived-experience payload")
    if not isinstance(payload["tags"], list) or not all(
        isinstance(tag, str) for tag in payload["tags"]
    ):
        raise SpikeError("event tags must be strings")
    embodiment = event["origin_embodiment"]
    if (
        not isinstance(embodiment, dict)
        or set(embodiment) != {"host", "harness"}
        or not all(isinstance(value, str) and value for value in embodiment.values())
    ):
        raise SpikeError("invalid origin embodiment")

    unsigned = {key: value for key, value in event.items() if key not in {"content_hash", "signature"}}
    digest = hashlib.sha256(canonical_bytes(unsigned)).hexdigest()
    if digest != event["content_hash"]:
        raise SpikeError("event content hash mismatch")
    public_text = config.get("trusted_incarnations", {}).get(event["origin_incarnation"])
    if not public_text:
        raise SpikeError(f"untrusted incarnation: {event['origin_incarnation']}")
    if public_key_id(public_text) != event["signing_key_id"]:
        raise SpikeError("event signing key ID mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(public_text)).verify(
            _unb64(event["signature"]), bytes.fromhex(digest)
        )
    except InvalidSignature as exc:
        raise SpikeError("event signature verification failed") from exc


class Ledger:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.path = state_dir / "ledger.db"

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    me_id TEXT NOT NULL,
                    origin_incarnation TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    content_hash TEXT NOT NULL UNIQUE,
                    envelope_json TEXT NOT NULL,
                    imported_from TEXT NOT NULL,
                    inserted_at TEXT NOT NULL,
                    UNIQUE(origin_incarnation, sequence)
                );
                CREATE TABLE IF NOT EXISTS projections (
                    event_id TEXT PRIMARY KEY REFERENCES events(event_id),
                    provider TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    projected_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL REFERENCES events(event_id),
                    receiver_incarnation TEXT NOT NULL,
                    status TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                """
            )
        os.chmod(self.path, 0o600)

    def local_sequence(self, incarnation_id: str) -> tuple[int, str | None]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT sequence, event_id FROM events WHERE origin_incarnation=? "
                "ORDER BY sequence DESC LIMIT 1",
                (incarnation_id,),
            ).fetchone()
        return (int(row["sequence"]), str(row["event_id"])) if row else (0, None)

    def envelopes(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT envelope_json FROM events ORDER BY origin_incarnation, sequence"
            ).fetchall()
        return [json.loads(row["envelope_json"]) for row in rows]

    def event_ids(self) -> set[str]:
        with self.connect() as connection:
            return {str(row[0]) for row in connection.execute("SELECT event_id FROM events")}

    def event_hashes(self) -> dict[str, str]:
        with self.connect() as connection:
            return {
                str(row["event_id"]): str(row["content_hash"])
                for row in connection.execute("SELECT event_id, content_hash FROM events")
            }

    def append(self, event: dict[str, Any], *, imported_from: str) -> str:
        envelope = canonical_bytes(event).decode("utf-8")
        try:
            with self.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO events(
                        event_id, me_id, origin_incarnation, sequence, occurred_at,
                        event_type, content_hash, envelope_json, imported_from, inserted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["event_id"],
                        event["me_id"],
                        event["origin_incarnation"],
                        event["sequence"],
                        event["occurred_at"],
                        event["event_type"],
                        event["content_hash"],
                        envelope,
                        imported_from,
                        utc_now(),
                    ),
                )
            return "inserted"
        except sqlite3.IntegrityError as exc:
            with self.connect() as connection:
                by_id = connection.execute(
                    "SELECT content_hash FROM events WHERE event_id=?",
                    (event["event_id"],),
                ).fetchone()
                by_sequence = connection.execute(
                    "SELECT event_id, content_hash FROM events "
                    "WHERE origin_incarnation=? AND sequence=?",
                    (event["origin_incarnation"], event["sequence"]),
                ).fetchone()
            if by_id and by_id["content_hash"] == event["content_hash"]:
                return "duplicate"
            if by_sequence:
                raise SpikeError(
                    "forked incarnation sequence: "
                    f"{event['origin_incarnation']}#{event['sequence']}"
                ) from exc
            raise SpikeError("event identity collision") from exc

    def projection(self, event_id: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM projections WHERE event_id=?", (event_id,)
            ).fetchone()

    def record_projection(self, event_id: str, provider: str, external_id: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO projections(event_id, provider, external_id, projected_at) "
                "VALUES (?, ?, ?, ?)",
                (event_id, provider, external_id, utc_now()),
            )

    def record_receipt(self, event_id: str, receiver: str, status: str) -> str:
        receipt_id = hashlib.sha256(
            f"{event_id}\0{receiver}\0{status}".encode("utf-8")
        ).hexdigest()
        with self.connect() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO receipts(receipt_id, event_id, receiver_incarnation, status, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (receipt_id, event_id, receiver, status, utc_now()),
            )
        return receipt_id

    def status(self) -> dict[str, Any]:
        with self.connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            projected = int(
                connection.execute("SELECT COUNT(*) FROM projections").fetchone()[0]
            )
            origins = [
                {
                    "incarnation": row["origin_incarnation"],
                    "sequence": int(row["sequence"]),
                    "events": int(row["events"]),
                }
                for row in connection.execute(
                    "SELECT origin_incarnation, MAX(sequence) AS sequence, COUNT(*) AS events "
                    "FROM events GROUP BY origin_incarnation ORDER BY origin_incarnation"
                )
            ]
            hashes = [
                str(row[0])
                for row in connection.execute(
                    "SELECT content_hash FROM events ORDER BY origin_incarnation, sequence"
                )
            ]
        head = hashlib.sha256("".join(hashes).encode("ascii")).hexdigest()
        return {
            "events": total,
            "projected": projected,
            "origins": origins,
            "head": head,
        }


@dataclass
class HmkProjector:
    config: dict[str, Any]

    @property
    def enabled(self) -> bool:
        hmk = self.config.get("hmk", {})
        return bool(hmk.get("wrapper") and hmk.get("base"))

    def project(self, event: dict[str, Any]) -> str:
        if not self.enabled:
            return "disabled"
        hmk = self.config["hmk"]
        payload = event["payload"]
        title = f"[dm-spike:{event['event_id'][:12]}] {payload['title']}"
        provenance = (
            "Experimental Daimon Matrix lived-experience event.\n"
            f"event_id: {event['event_id']}\n"
            f"origin_incarnation: {event['origin_incarnation']}\n"
            f"origin_host: {event['origin_embodiment']['host']}\n"
            f"origin_harness: {event['origin_embodiment']['harness']}\n"
            f"occurred_at: {event['occurred_at']}\n\n"
        )
        tags = list(payload["tags"]) + [
            "daimon-matrix-spike",
            f"dm-event:{event['event_id']}",
            f"incarnation:{event['origin_incarnation']}",
            f"host:{event['origin_embodiment']['host']}",
            f"harness:{event['origin_embodiment']['harness']}",
        ]
        environment = os.environ.copy()
        environment["HMK_AGENT_MEMORY_BASE"] = hmk["base"]
        if hmk.get("hermes_home"):
            environment["HERMES_HOME"] = hmk["hermes_home"]
        result = subprocess.run(
            [
                hmk["wrapper"],
                "memoryctl.py",
                "add-text",
                "--shelf",
                hmk.get("shelf", "episodes"),
                "--title",
                title,
                "--raw",
                provenance + payload["content"],
                "--tags",
                ",".join(tags),
                "--importance",
                "0.8",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
        )
        response = json.loads(result.stdout)
        if not response.get("ok"):
            raise SpikeError("HMK rejected the experimental projection")
        return str(response["chapter_id"])


def project_event(ledger: Ledger, config: dict[str, Any], event: dict[str, Any]) -> str:
    existing = ledger.projection(event["event_id"])
    if existing:
        return "duplicate"
    projector = HmkProjector(config)
    external_id = projector.project(event)
    ledger.record_projection(event["event_id"], "hmk" if projector.enabled else "none", external_id)
    return "projected"


def observe(
    state_dir: Path,
    *,
    title: str,
    content: str,
    tags: list[str],
) -> dict[str, Any]:
    config = load_config(state_dir)
    ledger = Ledger(state_dir)
    ledger.initialize()
    previous_sequence, previous_event_id = ledger.local_sequence(config["incarnation_id"])
    core = event_core(
        config,
        event_id=str(uuid.uuid4()),
        sequence=previous_sequence + 1,
        previous_event_id=previous_event_id,
        title=title,
        content=content,
        tags=tags,
    )
    event = sign_event(state_dir, core)
    validate_event(event, config)
    ledger.append(event, imported_from="local")
    projection = project_event(ledger, config, event)
    return {"event": event_summary(event), "projection": projection}


def event_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event["event_id"],
        "origin_incarnation": event["origin_incarnation"],
        "origin_embodiment": event["origin_embodiment"],
        "sequence": event["sequence"],
        "occurred_at": event["occurred_at"],
        "event_type": event["event_type"],
        "title": event["payload"]["title"],
        "content_hash": event["content_hash"],
    }


def preview(state_dir: Path, events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    config = load_config(state_dir)
    ledger = Ledger(state_dir)
    ledger.initialize()
    event_list = list(events)
    for event in event_list:
        validate_event(event, config)
    existing = ledger.event_hashes()
    missing = []
    duplicates = 0
    for event in event_list:
        if event["event_id"] in existing:
            if existing[event["event_id"]] != event["content_hash"]:
                raise SpikeError("event ID collision during incoming preview")
            duplicates += 1
        else:
            missing.append(event_summary(event))
    return {
        "receiver": config["incarnation_id"],
        "missing": missing,
        "missing_count": len(missing),
        "duplicate_count": duplicates,
        "mutated": False,
        "cursor": ledger.status(),
    }


def ingest(
    state_dir: Path,
    events: Iterable[dict[str, Any]],
    *,
    imported_from: str,
) -> dict[str, Any]:
    config = load_config(state_dir)
    ledger = Ledger(state_dir)
    ledger.initialize()
    event_list = list(events)
    # Fail the whole validation phase before appending any member of a bad
    # batch. Projection remains receiver-local and resumable after acceptance.
    for event in event_list:
        validate_event(event, config)
    inserted = 0
    duplicates = 0
    projected = 0
    receipts = []
    for event in event_list:
        result = ledger.append(event, imported_from=imported_from)
        inserted += result == "inserted"
        duplicates += result == "duplicate"
        projection = project_event(ledger, config, event)
        projected += projection == "projected"
        receipts.append(
            ledger.record_receipt(
                event["event_id"], config["incarnation_id"], "integrated"
            )
        )
    return {
        "receiver": config["incarnation_id"],
        "inserted": inserted,
        "duplicates": duplicates,
        "projected": projected,
        "receipts": receipts,
        "cursor": ledger.status(),
    }


class SshPeer:
    def __init__(self, state_dir: Path, peer_id: str):
        config = load_config(state_dir)
        try:
            self.peer = config["peers"][peer_id]
        except KeyError as exc:
            raise SpikeError(f"unknown peer: {peer_id}") from exc
        self.peer_id = peer_id

    def _command(self, operation: str) -> list[str]:
        return [
            "ssh",
            self.peer["ssh_host"],
            self.peer["remote_python"],
            "-m",
            "daimon_matrix.experimental_we.cli",
            "--state-dir",
            self.peer["remote_state_dir"],
            operation,
        ]

    def export(self) -> list[dict[str, Any]]:
        result = subprocess.run(
            self._command("export"),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout)["events"]

    def preview(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        result = subprocess.run(
            self._command("preview-stdin"),
            input=json.dumps({"events": events}),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return json.loads(result.stdout)

    def ingest(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        result = subprocess.run(
            self._command("ingest-stdin"),
            input=json.dumps({"events": events, "source": self.peer_id}),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return json.loads(result.stdout)


def incoming_from_peer(state_dir: Path, peer_id: str) -> dict[str, Any]:
    ledger = Ledger(state_dir)
    peer = SshPeer(state_dir, peer_id)
    peer_events = peer.export()
    return {
        "peer": peer_id,
        "incoming_to_local": preview(state_dir, peer_events),
        "incoming_to_peer": peer.preview(ledger.envelopes()),
    }


def pull_from_peer(state_dir: Path, peer_id: str) -> dict[str, Any]:
    peer = SshPeer(state_dir, peer_id)
    return ingest(
        state_dir,
        peer.export(),
        imported_from=f"ssh:{peer_id}",
    )


def sync_with_peer(
    state_dir: Path,
    peer_id: str,
    *,
    stop_after_push: bool = False,
) -> dict[str, Any]:
    ledger = Ledger(state_dir)
    peer = SshPeer(state_dir, peer_id)
    peer_before = peer.export()
    pushed = peer.ingest(ledger.envelopes())
    if stop_after_push:
        return {
            "peer": peer_id,
            "interrupted": True,
            "phase": "after_push",
            "pushed": pushed,
            "local_cursor": ledger.status(),
        }
    pulled = ingest(
        state_dir,
        peer_before,
        imported_from=f"ssh:{peer_id}",
    )
    peer_after = peer.export()
    # The remote may have learned local events during push; ingesting its final
    # view makes the coordinator safe if the peer already had third-party data.
    completed = ingest(
        state_dir,
        peer_after,
        imported_from=f"ssh:{peer_id}:final",
    )
    return {
        "peer": peer_id,
        "interrupted": False,
        "pushed": pushed,
        "pulled": pulled,
        "completed": completed,
        "local_cursor": ledger.status(),
        "peer_cursor": pushed["cursor"],
    }
