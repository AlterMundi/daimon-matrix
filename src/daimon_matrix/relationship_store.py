"""Durable multi-being relationship history and deterministic V1 reduction.

The ordinary Matrix ledger remains one-being authority.  This owner-local store
retains already verified ``dm.we.v1`` relationship events from several beings
without turning transport arrival, a directory row, or this database into
relationship authority.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import stat
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from .canonical import b64url, canonical_bytes
from .relationships import (
    RELATIONSHIP_EVENT_KINDS,
    TRIBE_SNAPSHOT_SCHEMA,
    RelationshipError,
    VerifiedTribeSnapshot,
    relationship_event_subject,
    validate_relationship_event_payload,
)
from .weave import EventAuthority, WeaveProtocolError, verify_event

SCHEMA_VERSION: Final = 1
BUSY_TIMEOUT_MS: Final = 5_000
CURSOR_DOMAIN: Final = b"daimon/relationship/cursor/v1\x00"
LINEAGE_DOMAIN: Final = b"daimon/relationship/tribe-lineage/v1\x00"


class RelationshipStoreError(RuntimeError):
    """Stable fail-closed storage or history error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RelationshipAuthorityResolver(Protocol):
    def __call__(self, being_ref: str) -> EventAuthority: ...


CardVerifier = Callable[[Mapping[str, Any], int], None]


@dataclass(frozen=True)
class RelationshipServiceContext:
    """Owner-local store plus the control/card verifier used by the daemon."""

    store: RelationshipStore
    card_verifier: CardVerifier


def _assert_owner_directory(path: Path) -> None:
    if path.is_symlink():
        raise RelationshipStoreError("relationship_parent_symlink")
    try:
        info = path.stat()
    except FileNotFoundError as exception:
        raise RelationshipStoreError("relationship_parent_missing") from exception
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RelationshipStoreError("relationship_parent_not_owner_only")


def _assert_owner_file(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise RelationshipStoreError("relationship_store_not_owner_only")


def _prepare_path(path: Path) -> None:
    if not path.parent.exists():
        missing: list[Path] = []
        current = path.parent
        while not current.exists():
            if current.is_symlink() or current == current.parent:
                raise RelationshipStoreError("relationship_parent_missing")
            missing.append(current)
            current = current.parent
        for directory in reversed(missing):
            with suppress(FileExistsError):
                directory.mkdir(mode=0o700)
            _assert_owner_directory(directory)
    _assert_owner_directory(path.parent)
    _assert_owner_file(path)
    if not path.exists():
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            _assert_owner_file(path)
        else:
            os.close(descriptor)


def _event_reference_ids(payload: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            if set(value) == {"event_hash", "event_id"}:
                result.add(cast(str, value["event_id"]))
            else:
                for item in value.values():
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    for field in ("previous_card_event_id", "previous_delegation_event_id"):
        value = payload.get(field)
        if isinstance(value, str):
            result.add(value)
    return result


def _event_ref_matches(reference: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    return bool(
        reference["event_id"] == event["event_id"]
        and reference["event_hash"] == event["content_hash"]
    )


def _is_current_card(
    cards: Mapping[str, Mapping[str, Any]], event: Mapping[str, Any]
) -> bool:
    current = cards.get(cast(str, event["payload"]["being_ref"]), {}).get("current")
    return bool(
        current is not None
        and current["event_id"] == event["event_id"]
        and current["content_hash"] == event["content_hash"]
    )


def _single_ref(
    reference: Mapping[str, Any], events: Mapping[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    candidates = events.get(cast(str, reference["event_id"]), [])
    matching = [event for event in candidates if _event_ref_matches(reference, event)]
    return matching[0] if len(matching) == 1 and len(candidates) == 1 else None


def _participant_pair(payload: Mapping[str, Any]) -> frozenset[str]:
    return frozenset(
        {
            cast(str, payload["initiator_being_ref"]),
            cast(str, payload["responder_being_ref"]),
        }
    )


def _permission_map(
    payload: Mapping[str, Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for permission in cast(list[dict[str, Any]], payload["permissions"]):
        for operation in permission["operations"]:
            result[(permission["resource_ref"], operation)] = permission
    return result


def _permission_is_attenuated(
    child: Mapping[str, Any], parent: Mapping[str, Any]
) -> bool:
    return bool(
        child["resource_ref"] == parent["resource_ref"]
        and child["classification"] == parent["classification"]
        and parent["delegable"]
        and parent["remaining_delegation_depth"] > 0
        and (
            not child["delegable"]
            or (
                parent["delegable"]
                and child["remaining_delegation_depth"]
                <= parent["remaining_delegation_depth"] - 1
            )
        )
        and (child["delegable"] or child["remaining_delegation_depth"] == 0)
    )


class RelationshipStore:
    """Owner-local exact-byte store for verified events from multiple beings."""

    def __init__(
        self,
        path: str | Path,
        *,
        authority_resolver: RelationshipAuthorityResolver,
    ) -> None:
        self.path = Path(os.path.abspath(path))
        self.authority_resolver = authority_resolver

    def _connect(self) -> sqlite3.Connection:
        _prepare_path(self.path)
        database = sqlite3.connect(
            self.path,
            timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None,
        )
        try:
            database.row_factory = sqlite3.Row
            database.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            database.execute("PRAGMA foreign_keys=ON")
            if (
                str(
                    database.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
                ).lower()
                != "delete"
            ):
                raise RelationshipStoreError("unsupported_relationship_journal")
            database.execute("PRAGMA synchronous=FULL")
        except Exception:
            database.close()
            raise
        return database

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        database: sqlite3.Connection | None = None
        try:
            database = self._connect()
            yield database
        except sqlite3.Error as exception:
            raise RelationshipStoreError("relationship_store_corrupt") from exception
        finally:
            if database is not None:
                database.close()

    def initialize(self) -> None:
        with self._database() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    being_ref TEXT NOT NULL,
                    embodiment_id TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    event_json BLOB NOT NULL,
                    inserted_order INTEGER PRIMARY KEY AUTOINCREMENT,
                    UNIQUE(event_id, content_hash)
                );
                CREATE INDEX IF NOT EXISTS relationship_event_id
                    ON events(event_id);
                CREATE INDEX IF NOT EXISTS relationship_origin_position
                    ON events(being_ref, incarnation_id, sequence);
                CREATE INDEX IF NOT EXISTS relationship_kind_subject
                    ON events(kind, subject);
                CREATE TABLE IF NOT EXISTS operations (
                    request_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    content_hash TEXT NOT NULL
                ) WITHOUT ROWID;
                """
            )
            row = database.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                database.execute(
                    "INSERT INTO metadata VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
            elif row["value"] != str(SCHEMA_VERSION):
                raise RelationshipStoreError("relationship_schema_mismatch")
            if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RelationshipStoreError("relationship_integrity_failed")

    def _validated_event(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise RelationshipStoreError("relationship_event_rejected")
        being_ref = value.get("being_ref")
        if not isinstance(being_ref, str):
            raise RelationshipStoreError("relationship_event_rejected")
        try:
            authority = self.authority_resolver(being_ref)
            event = verify_event(value, authority)
        except (KeyError, RelationshipError, WeaveProtocolError) as exception:
            raise RelationshipStoreError("relationship_event_rejected") from exception
        if event["kind"] not in RELATIONSHIP_EVENT_KINDS:
            raise RelationshipStoreError("relationship_event_rejected")
        try:
            payload = validate_relationship_event_payload(
                event["kind"],
                event["payload"],
                author_being_ref=event["being_ref"],
                causal_parents=event["causal_parents"],
            )
        except RelationshipError as exception:
            raise RelationshipStoreError("relationship_event_rejected") from exception
        if event["subject"] != relationship_event_subject(event["kind"], payload):
            raise RelationshipStoreError("relationship_event_rejected")
        return copy.deepcopy(event)

    def ingest(self, value: Any) -> dict[str, Any]:
        event = self._validated_event(value)
        raw = canonical_bytes(event)
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                database.execute(
                    "INSERT OR IGNORE INTO events "
                    "(event_id, content_hash, being_ref, embodiment_id, "
                    "incarnation_id, sequence, kind, subject, event_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event["event_id"],
                        event["content_hash"],
                        event["being_ref"],
                        event["origin"]["embodiment_id"],
                        event["origin"]["incarnation_id"],
                        event["sequence"],
                        event["kind"],
                        event["subject"],
                        raw,
                    ),
                )
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return copy.deepcopy(event)

    def ingest_idempotent(
        self, *, request_id: str, request_hash: str, event: Any
    ) -> dict[str, Any]:
        if (
            not isinstance(request_id, str)
            or not request_id
            or not isinstance(request_hash, str)
            or len(request_hash) != 64
            or any(character not in "0123456789abcdef" for character in request_hash)
        ):
            raise RelationshipStoreError("invalid_relationship_request")
        validated = self._validated_event(event)
        raw = canonical_bytes(validated)
        self.initialize()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                existing = database.execute(
                    "SELECT request_hash, event_id, content_hash FROM operations "
                    "WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise RelationshipStoreError("relationship_request_conflict")
                    row = database.execute(
                        "SELECT event_json FROM events "
                        "WHERE event_id=? AND content_hash=?",
                        (existing["event_id"], existing["content_hash"]),
                    ).fetchone()
                    if row is None:
                        raise RelationshipStoreError("relationship_operation_corrupt")
                    result = json.loads(bytes(row["event_json"]))
                else:
                    database.execute(
                        "INSERT OR IGNORE INTO events "
                        "(event_id, content_hash, being_ref, embodiment_id, "
                        "incarnation_id, sequence, kind, subject, event_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            validated["event_id"],
                            validated["content_hash"],
                            validated["being_ref"],
                            validated["origin"]["embodiment_id"],
                            validated["origin"]["incarnation_id"],
                            validated["sequence"],
                            validated["kind"],
                            validated["subject"],
                            raw,
                        ),
                    )
                    database.execute(
                        "INSERT INTO operations VALUES (?, ?, ?, ?)",
                        (
                            request_id,
                            request_hash,
                            validated["event_id"],
                            validated["content_hash"],
                        ),
                    )
                    result = validated
                database.commit()
            except BaseException:
                database.rollback()
                raise
        return copy.deepcopy(result)

    def events(self) -> list[dict[str, Any]]:
        self.initialize()
        with self._database() as database:
            rows = database.execute(
                "SELECT event_json FROM events ORDER BY being_ref, incarnation_id, "
                "sequence, content_hash"
            ).fetchall()
        return [json.loads(bytes(row["event_json"])) for row in rows]

    def cursor(self) -> dict[str, Any]:
        events = self.events()
        variants = [
            {"event_hash": event["content_hash"], "event_id": event["event_id"]}
            for event in sorted(
                events, key=lambda item: (item["event_id"], item["content_hash"])
            )
        ]
        body = {"schema": "dm.relationship.cursor/v1", "events": variants}
        return {
            **body,
            "cursor_hash": b64url(
                hashlib.sha256(CURSOR_DOMAIN + canonical_bytes(body)).digest()
            ),
        }

    def view(
        self, *, at_ms: int, card_verifier: CardVerifier | None
    ) -> RelationshipView:
        return RelationshipView(self.events(), at_ms=at_ms, card_verifier=card_verifier)


class RelationshipView:
    """Pure deterministic reduction of retained signed relationship evidence."""

    def __init__(
        self,
        events: Sequence[Mapping[str, Any]],
        *,
        at_ms: int,
        card_verifier: CardVerifier | None,
    ) -> None:
        if not isinstance(at_ms, int) or isinstance(at_ms, bool) or at_ms < 0:
            raise RelationshipStoreError("invalid_relationship_time")
        self.at_ms = at_ms
        self.card_verifier = card_verifier
        self.all_events = [copy.deepcopy(dict(event)) for event in events]
        effective_events = [
            event
            for event in self.all_events
            if cast(int, event["occurred_at_ms"]) <= at_ms
        ]
        self.by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.by_position: dict[tuple[str, str, int], list[dict[str, Any]]] = (
            defaultdict(list)
        )
        for event in effective_events:
            self.by_id[event["event_id"]].append(event)
            self.by_position[
                (
                    event["being_ref"],
                    event["origin"]["incarnation_id"],
                    event["sequence"],
                )
            ].append(event)
        self.forked_event_ids: set[str] = set()
        fork_cutoffs: dict[tuple[str, str], int] = {}
        for variants in self.by_id.values():
            if len({event["content_hash"] for event in variants}) > 1:
                self.forked_event_ids.update(event["event_id"] for event in variants)
        for position, variants in self.by_position.items():
            if len({event["content_hash"] for event in variants}) > 1:
                self.forked_event_ids.update(event["event_id"] for event in variants)
                origin = (position[0], position[1])
                fork_cutoffs[origin] = min(
                    position[2], fork_cutoffs.get(origin, position[2])
                )
        for event in effective_events:
            origin = (event["being_ref"], event["origin"]["incarnation_id"])
            if origin in fork_cutoffs and event["sequence"] >= fork_cutoffs[origin]:
                self.forked_event_ids.add(event["event_id"])
        candidates = {
            event["event_id"]: event
            for event in self.all_events
            if event["event_id"] not in self.forked_event_ids
            and len(self.by_id[event["event_id"]]) == 1
        }
        complete_by_id: dict[str, dict[str, Any]] = {}
        pending = dict(candidates)
        while pending:
            progressed = False
            for event_id, event in list(pending.items()):
                references = _event_reference_ids(event["payload"])
                if references.issubset(complete_by_id):
                    complete_by_id[event_id] = event
                    del pending[event_id]
                    progressed = True
            if not progressed:
                break
        self.complete = sorted(
            complete_by_id.values(),
            key=lambda event: (
                event["being_ref"],
                event["origin"]["incarnation_id"],
                event["sequence"],
            ),
        )
        self.kind: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.complete:
            self.kind[event["kind"]].append(event)
        self.cards = self._cards()
        self.relationships = self._relationships()
        self.tribes = self._tribes()
        self.grants = self._grants()

    def _cards(self) -> dict[str, dict[str, Any]]:
        grouped: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for event in self.kind["matrix/relationship-card"]:
            payload = event["payload"]
            grouped[payload["being_ref"]][payload["sequence"]].append(event)
        result: dict[str, dict[str, Any]] = {}
        for being_ref, positions in grouped.items():
            accepted: list[dict[str, Any]] = []
            previous: str | None = None
            sequence = 0
            while sequence in positions:
                variants = positions[sequence]
                if len(variants) != 1:
                    accepted = []
                    break
                event = variants[0]
                if event["payload"]["previous_card_event_id"] != previous:
                    accepted = []
                    break
                accepted.append(event)
                previous = event["event_id"]
                sequence += 1
            if set(positions) != set(range(sequence)):
                accepted = []
            if not accepted:
                continue
            current = [
                event
                for event in accepted
                if event["payload"]["issued_at_ms"]
                <= self.at_ms
                < event["payload"]["expires_at_ms"]
            ]
            active = current[-1] if current else None
            if active is not None:
                if self.card_verifier is None:
                    active = None
                else:
                    try:
                        self.card_verifier(active["payload"], self.at_ms)
                    except (RelationshipError, ValueError):
                        active = None
            result[being_ref] = {
                "history": accepted,
                "latest": accepted[-1],
                "current": active,
                "forked": False,
            }
        return result

    def _relationships(self) -> dict[str, dict[str, Any]]:
        offers: dict[str, list[dict[str, Any]]] = defaultdict(list)
        acceptances: dict[str, list[dict[str, Any]]] = defaultdict(list)
        closes: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.kind["matrix/relationship-offer"]:
            offers[event["payload"]["relationship_id"]].append(event)
        for event in self.kind["matrix/relationship-acceptance"]:
            acceptances[event["payload"]["relationship_id"]].append(event)
        for event in self.kind["matrix/relationship-close"]:
            closes[event["payload"]["relationship_id"]].append(event)
        result: dict[str, dict[str, Any]] = {}
        for relationship, candidates in offers.items():
            if len(candidates) != 1:
                result[relationship] = {"state": "forked"}
                continue
            offer = candidates[0]
            payload = offer["payload"]
            initiator_card = _single_ref(payload["initiator_card_ref"], self.by_id)
            responder_ref = payload["responder_card_ref"]
            if initiator_card is None or (
                responder_ref is not None
                and _single_ref(responder_ref, self.by_id) is None
            ):
                result[relationship] = {"state": "incomplete", "offer": offer}
                continue
            valid_acceptances: list[dict[str, Any]] = []
            for acceptance in acceptances.get(relationship, []):
                accepted = acceptance["payload"]
                responder_card = _single_ref(accepted["responder_card_ref"], self.by_id)
                if (
                    _event_ref_matches(accepted["offer_ref"], offer)
                    and accepted["initiator_being_ref"]
                    == payload["initiator_being_ref"]
                    and accepted["responder_being_ref"]
                    == payload["responder_being_ref"]
                    and accepted["initiator_card_ref"] == payload["initiator_card_ref"]
                    and (
                        responder_ref is None
                        or accepted["responder_card_ref"] == responder_ref
                    )
                    and responder_card is not None
                    and responder_card["payload"]["being_ref"]
                    == payload["responder_being_ref"]
                    and payload["issued_at_ms"]
                    <= accepted["accepted_at_ms"]
                    < payload["expires_at_ms"]
                ):
                    valid_acceptances.append(acceptance)
            if not valid_acceptances:
                result[relationship] = {"state": "offered", "offer": offer}
                continue
            if len(valid_acceptances) != 1:
                result[relationship] = {"state": "forked", "offer": offer}
                continue
            valid_closes = [
                event
                for event in closes.get(relationship, [])
                if event["payload"]["closer_being_ref"] in _participant_pair(payload)
                and _event_ref_matches(event["payload"]["offer_ref"], offer)
                and any(
                    _event_ref_matches(event["payload"]["acceptance_ref"], item)
                    for item in valid_acceptances
                )
            ]
            relationship_cards = [initiator_card]
            relationship_cards.extend(
                cast(
                    dict[str, Any],
                    _single_ref(event["payload"]["responder_card_ref"], self.by_id),
                )
                for event in valid_acceptances
            )
            cards_current = all(
                _is_current_card(self.cards, card) for card in relationship_cards
            )
            result[relationship] = {
                "state": (
                    "closed"
                    if valid_closes
                    else "active"
                    if cards_current
                    else "stale-card"
                ),
                "bilateral": True,
                "offer": offer,
                "acceptances": valid_acceptances,
                "closes": valid_closes,
                "participants": sorted(_participant_pair(payload)),
            }
        return result

    def _card_valid_at(self, event: Mapping[str, Any], at_ms: int) -> bool:
        payload = event["payload"]
        if not payload["issued_at_ms"] <= at_ms < payload["expires_at_ms"]:
            return False
        if self.card_verifier is None:
            return False
        try:
            self.card_verifier(payload, at_ms)
        except (RelationshipError, ValueError):
            return False
        return True

    def _relationship_active_at(
        self, relationship: Mapping[str, Any], at_ms: int
    ) -> bool:
        if relationship.get("bilateral") is not True:
            return False
        offer = relationship["offer"]
        acceptance = relationship["acceptances"][0]
        initiator_card = _single_ref(offer["payload"]["initiator_card_ref"], self.by_id)
        responder_card = _single_ref(
            acceptance["payload"]["responder_card_ref"], self.by_id
        )
        return bool(
            acceptance["payload"]["accepted_at_ms"] <= at_ms
            and not any(
                close["payload"]["closed_at_ms"] <= at_ms
                for close in relationship["closes"]
            )
            and initiator_card is not None
            and responder_card is not None
            and self._card_valid_at(initiator_card, at_ms)
            and self._card_valid_at(responder_card, at_ms)
        )

    def _tribes(self) -> dict[str, dict[str, Any]]:
        declarations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.kind["matrix/tribe-declaration"]:
            declarations[event["payload"]["tribe_ref"]].append(event)
        result: dict[str, dict[str, Any]] = {}
        for tribe, candidates in declarations.items():
            if len(candidates) != 1:
                result[tribe] = {"state": "forked"}
                continue
            declaration = candidates[0]
            founder = declaration["payload"]["declaration"]["founder_principal_id"]
            founder_by_epoch: dict[int, str] = {0: founder}
            epoch_started_at: dict[int, int] = {
                0: declaration["payload"]["declaration"]["created_at_ms"]
            }
            state = "active"
            epoch = 0
            while True:
                transfers = [
                    event
                    for event in self.kind["matrix/tribe-founder-transfer"]
                    if event["payload"]["tribe_ref"] == tribe
                    and event["payload"]["from_epoch"] == epoch
                    and event["payload"]["old_founder_being_ref"]
                    == founder_by_epoch[epoch]
                    and event["payload"]["issued_at_ms"] >= epoch_started_at[epoch]
                ]
                if not transfers:
                    break
                if len(transfers) != 1:
                    state = "forked"
                    break
                transfer = transfers[0]
                acceptances = [
                    event
                    for event in self.kind["matrix/tribe-founder-acceptance"]
                    if event["payload"]["tribe_ref"] == tribe
                    and event["payload"]["transfer_id"]
                    == transfer["payload"]["transfer_id"]
                    and _event_ref_matches(event["payload"]["transfer_ref"], transfer)
                    and event["payload"]["successor_being_ref"]
                    == transfer["payload"]["successor_being_ref"]
                    and event["payload"]["accepted_at_ms"]
                    >= transfer["payload"]["issued_at_ms"]
                ]
                if not acceptances:
                    break
                if len(acceptances) != 1:
                    state = "forked"
                    break
                epoch += 1
                founder_by_epoch[epoch] = transfer["payload"]["successor_being_ref"]
                epoch_started_at[epoch] = acceptances[0]["payload"]["accepted_at_ms"]

            def epoch_is_current(
                candidate: int,
                at_ms: int,
                timeline: Mapping[int, int] = epoch_started_at,
            ) -> bool:
                started = timeline.get(candidate)
                ended = timeline.get(candidate + 1)
                return bool(
                    started is not None
                    and started <= at_ms
                    and (ended is None or at_ms < ended)
                )

            memberships: dict[str, dict[str, Any]] = {
                founder: {
                    "state": "active",
                    "membership_event": declaration,
                    "terminal_event": None,
                    "episodes": [],
                }
            }
            invitations: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for event in self.kind["matrix/tribe-invitation"]:
                if event["payload"]["tribe_ref"] == tribe:
                    invitations[event["payload"]["invitation_id"]].append(event)
            membership_positions: dict[str, dict[int, list[dict[str, Any]]]] = (
                defaultdict(lambda: defaultdict(list))
            )
            forked_members: set[str] = set()
            for invite_variants in invitations.values():
                invitees = {
                    event["payload"]["invitee_being_ref"] for event in invite_variants
                }
                if len(invite_variants) != 1:
                    forked_members.update(invitees)
                    continue
                invitation = invite_variants[0]
                invitation_payload = invitation["payload"]
                invite_epoch = invitation_payload["founder_epoch"]
                if founder_by_epoch.get(invite_epoch) != invitation_payload[
                    "founder_being_ref"
                ] or not epoch_is_current(
                    invite_epoch, invitation_payload["issued_at_ms"]
                ):
                    continue
                if not any(
                    self._relationship_active_at(
                        relationship, invitation_payload["issued_at_ms"]
                    )
                    and set(relationship["participants"])
                    == {
                        invitation_payload["founder_being_ref"],
                        invitation_payload["invitee_being_ref"],
                    }
                    for relationship in self.relationships.values()
                ):
                    continue
                accepted = [
                    event
                    for event in self.kind["matrix/tribe-membership-acceptance"]
                    if event["payload"]["tribe_ref"] == tribe
                    and event["payload"]["founder_epoch"] == invite_epoch
                    and event["payload"]["invitee_being_ref"]
                    == invitation_payload["invitee_being_ref"]
                    and _event_ref_matches(
                        event["payload"]["invitation_ref"], invitation
                    )
                    and invitation_payload["issued_at_ms"]
                    <= event["payload"]["accepted_at_ms"]
                    < invitation_payload["expires_at_ms"]
                ]
                if not accepted:
                    continue
                member = invitation_payload["invitee_being_ref"]
                if len(accepted) != 1:
                    forked_members.add(member)
                    continue
                acceptance = accepted[0]
                membership_positions[member][
                    acceptance["payload"]["membership_sequence"]
                ].append(acceptance)
            for member in sorted(set(membership_positions) | forked_members):
                positions = membership_positions.get(member, {})
                episodes: list[dict[str, Any]] = []
                expected_previous: dict[str, Any] | None = None
                sequence = 0
                lane_forked = member in forked_members
                while not lane_forked and sequence in positions:
                    candidates = positions[sequence]
                    if len(candidates) != 1:
                        lane_forked = True
                        break
                    acceptance = candidates[0]
                    previous = acceptance["payload"]["previous_membership_terminal_ref"]
                    if (previous is None) != (expected_previous is None) or (
                        previous is not None
                        and expected_previous is not None
                        and not _event_ref_matches(previous, expected_previous)
                    ):
                        lane_forked = True
                        break
                    accepted_at = acceptance["payload"]["accepted_at_ms"]
                    terminals: list[tuple[str, dict[str, Any]]] = []
                    terminals.extend(
                        ("left", event)
                        for event in self.kind["matrix/tribe-membership-leave"]
                        if event["payload"]["tribe_ref"] == tribe
                        and event["payload"]["member_being_ref"] == member
                        and event["payload"]["terminated_at_ms"] >= accepted_at
                        and epoch_is_current(
                            event["payload"]["founder_epoch"],
                            event["payload"]["terminated_at_ms"],
                        )
                        and _event_ref_matches(
                            event["payload"]["membership_acceptance_ref"],
                            acceptance,
                        )
                    )
                    terminals.extend(
                        ("expelled", event)
                        for event in self.kind["matrix/tribe-membership-expulsion"]
                        if event["payload"]["tribe_ref"] == tribe
                        and event["payload"]["member_being_ref"] == member
                        and event["payload"]["terminated_at_ms"] >= accepted_at
                        and epoch_is_current(
                            event["payload"]["founder_epoch"],
                            event["payload"]["terminated_at_ms"],
                        )
                        and founder_by_epoch.get(event["payload"]["founder_epoch"])
                        == event["payload"]["founder_being_ref"]
                        and _event_ref_matches(
                            event["payload"]["membership_acceptance_ref"],
                            acceptance,
                        )
                    )
                    if len(terminals) > 1:
                        lane_forked = True
                        break
                    terminal_state = "active"
                    terminal: dict[str, Any] | None = None
                    if terminals:
                        terminal_state, terminal = terminals[0]
                    episodes.append(
                        {
                            "membership_event": acceptance,
                            "state": terminal_state,
                            "terminal_event": terminal,
                        }
                    )
                    sequence += 1
                    if terminal is None:
                        if any(position >= sequence for position in positions):
                            lane_forked = True
                        break
                    expected_previous = terminal
                if set(positions) != set(range(sequence)):
                    lane_forked = True
                if lane_forked or not episodes:
                    memberships[member] = {
                        "state": "forked",
                        "membership_event": (
                            episodes[-1]["membership_event"] if episodes else None
                        ),
                        "terminal_event": (
                            episodes[-1]["terminal_event"] if episodes else None
                        ),
                        "episodes": episodes,
                    }
                    continue
                latest = episodes[-1]
                memberships[member] = {**latest, "episodes": episodes}

            def membership_active_at(
                member: str,
                at_ms: int,
                original_founder: str = founder,
                member_states: Mapping[str, Mapping[str, Any]] = memberships,
            ) -> bool:
                if member == original_founder:
                    return True
                membership = member_states.get(member)
                if membership is None or membership["state"] == "forked":
                    return False
                return any(
                    episode["membership_event"]["payload"]["accepted_at_ms"] <= at_ms
                    and (
                        episode["terminal_event"] is None
                        or at_ms
                        < episode["terminal_event"]["payload"]["terminated_at_ms"]
                    )
                    for episode in membership["episodes"]
                )

            if any(
                not membership_active_at(founder_by_epoch[position], started_at)
                for position, started_at in epoch_started_at.items()
                if position > 0
            ):
                state = "forked"
            current_founder = founder_by_epoch[epoch]
            if (
                current_founder not in memberships
                or memberships[current_founder]["state"] != "active"
            ):
                state = "forked"
            result[tribe] = {
                "state": state,
                "declaration": declaration,
                "founder_epoch": epoch,
                "founder_being_ref": current_founder,
                "founder_by_epoch": founder_by_epoch,
                "epoch_started_at": epoch_started_at,
                "memberships": memberships,
            }
        return result

    def _grant_is_bounded_by_offer(
        self, grant: Mapping[str, Any], offer: Mapping[str, Any]
    ) -> bool:
        payload = grant["payload"]
        child_map = _permission_map(payload)
        for proposed in offer["payload"]["proposed_grants"]:
            if (
                proposed["grantor_being_ref"] == payload["grantor_being_ref"]
                and proposed["subject_being_ref"] == payload["subject_being_ref"]
                and proposed["not_before_ms"] <= payload["not_before_ms"]
                and payload["expires_at_ms"] <= proposed["expires_at_ms"]
            ):
                parent_map = _permission_map(proposed)
                if all(
                    key in parent_map
                    and permission["classification"]
                    == parent_map[key]["classification"]
                    and (permission["delegable"] <= parent_map[key]["delegable"])
                    and permission["remaining_delegation_depth"]
                    <= parent_map[key]["remaining_delegation_depth"]
                    for key, permission in child_map.items()
                ):
                    return True
        return False

    def _grants(self) -> dict[str, dict[str, Any]]:
        grants: dict[str, list[dict[str, Any]]] = defaultdict(list)
        acceptances: dict[str, list[dict[str, Any]]] = defaultdict(list)
        revocations: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self.kind["matrix/relationship-grant"]:
            grants[event["payload"]["grant_id"]].append(event)
        for event in self.kind["matrix/relationship-grant-acceptance"]:
            acceptances[event["payload"]["grant_id"]].append(event)
        for event in self.kind["matrix/relationship-grant-revocation"]:
            revocations[event["payload"]["grant_id"]].append(event)
        lane_positions: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for candidates in grants.values():
            for event in candidates:
                parent_ref = event["payload"]["parent_grant_ref"]
                if parent_ref is not None:
                    lane_positions[
                        (
                            parent_ref["event_id"],
                            event["payload"]["delegation_sequence"],
                        )
                    ].append(event)
        lane_fork_cutoffs: dict[str, int] = {}
        for (parent_event_id, sequence), events in lane_positions.items():
            if len({event["event_id"] for event in events}) > 1:
                lane_fork_cutoffs[parent_event_id] = min(
                    sequence, lane_fork_cutoffs.get(parent_event_id, sequence)
                )
        result: dict[str, dict[str, Any]] = {}
        pending = set(grants)
        while pending:
            progressed = False
            for identifier in sorted(pending):
                candidates = grants[identifier]
                if len(candidates) != 1:
                    result[identifier] = {"state": "forked"}
                    pending.remove(identifier)
                    progressed = True
                    break
                grant = candidates[0]
                payload = grant["payload"]
                parent_ref = payload["parent_grant_ref"]
                if parent_ref is not None and payload[
                    "delegation_sequence"
                ] >= lane_fork_cutoffs.get(parent_ref["event_id"], 2**53):
                    result[identifier] = {"state": "forked", "grant": grant}
                    pending.remove(identifier)
                    progressed = True
                    break
                relationship = self.relationships.get(payload["relationship_id"])
                if relationship is None or relationship.get("bilateral") is not True:
                    result[identifier] = {"state": "incomplete", "grant": grant}
                    pending.remove(identifier)
                    progressed = True
                    break
                if not self._relationship_active_at(
                    relationship, payload["issued_at_ms"]
                ):
                    result[identifier] = {"state": "invalid", "grant": grant}
                    pending.remove(identifier)
                    progressed = True
                    break
                if set(relationship["participants"]) != {
                    payload["grantor_being_ref"],
                    payload["subject_being_ref"],
                }:
                    result[identifier] = {"state": "invalid", "grant": grant}
                    pending.remove(identifier)
                    progressed = True
                    break
                parent_state: dict[str, Any] | None = None
                if parent_ref is None:
                    offer_payload = relationship["offer"]["payload"]
                    card_ref = (
                        offer_payload["initiator_card_ref"]
                        if offer_payload["initiator_being_ref"]
                        == payload["grantor_being_ref"]
                        else relationship["acceptances"][0]["payload"][
                            "responder_card_ref"
                        ]
                    )
                    grantor_card = _single_ref(card_ref, self.by_id)
                    resource_map = (
                        {
                            item["resource_ref"]: item["descriptor"]
                            for item in grantor_card["payload"]["resources"]
                        }
                        if grantor_card is not None
                        else {}
                    )
                    descriptor_valid = all(
                        permission["resource_ref"] in resource_map
                        and resource_map[permission["resource_ref"]][
                            "controller_being_ref"
                        ]
                        == payload["grantor_being_ref"]
                        and permission["classification"]
                        == resource_map[permission["resource_ref"]]["classification"]
                        and set(permission["operations"]).issubset(
                            resource_map[permission["resource_ref"]]["operations"]
                        )
                        for permission in payload["permissions"]
                    )
                    if not descriptor_valid or not self._grant_is_bounded_by_offer(
                        grant, relationship["offer"]
                    ):
                        result[identifier] = {"state": "invalid", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                else:
                    parent_event = _single_ref(parent_ref, self.by_id)
                    if parent_event is None:
                        result[identifier] = {"state": "incomplete", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                    parent_id = parent_event["payload"]["grant_id"]
                    if parent_id in pending:
                        continue
                    parent_state = result.get(parent_id)
                    if parent_state is None:
                        result[identifier] = {"state": "incomplete", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                    if parent_state["state"] == "forked":
                        result[identifier] = {"state": "forked", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                    if parent_state["state"] not in {
                        "active",
                        "expired",
                        "revoked",
                        "revoked+relinquished",
                        "relinquished",
                        "closed",
                    }:
                        result[identifier] = {"state": "invalid", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                    sequence = payload["delegation_sequence"]
                    if sequence > 0:
                        preceding = lane_positions.get(
                            (parent_ref["event_id"], sequence - 1), []
                        )
                        if (
                            len(preceding) != 1
                            or payload["previous_delegation_event_id"]
                            != preceding[0]["event_id"]
                        ):
                            result[identifier] = {
                                "state": "incomplete",
                                "grant": grant,
                            }
                            pending.remove(identifier)
                            progressed = True
                            break
                        preceding_id = preceding[0]["payload"]["grant_id"]
                        if preceding_id in pending:
                            continue
                        preceding_state = result.get(preceding_id)
                        if (
                            preceding_state is None
                            or not preceding_state.get("acceptances")
                            or preceding_state["state"]
                            in {"forked", "incomplete", "invalid", "offered"}
                        ):
                            result[identifier] = {
                                "state": "incomplete",
                                "grant": grant,
                            }
                            pending.remove(identifier)
                            progressed = True
                            break
                    parent_payload = parent_event["payload"]
                    parent_map = _permission_map(parent_payload)
                    child_map = _permission_map(payload)
                    if (
                        parent_payload["subject_being_ref"]
                        != payload["grantor_being_ref"]
                        or payload["not_before_ms"] < parent_payload["not_before_ms"]
                        or payload["expires_at_ms"] > parent_payload["expires_at_ms"]
                        or not all(
                            key in parent_map
                            and _permission_is_attenuated(permission, parent_map[key])
                            for key, permission in child_map.items()
                        )
                    ):
                        result[identifier] = {"state": "invalid", "grant": grant}
                        pending.remove(identifier)
                        progressed = True
                        break
                valid_acceptances = [
                    event
                    for event in acceptances.get(identifier, [])
                    if _event_ref_matches(event["payload"]["grant_ref"], grant)
                    and event["payload"]["relationship_id"]
                    == payload["relationship_id"]
                    and event["payload"]["grantor_being_ref"]
                    == payload["grantor_being_ref"]
                    and event["payload"]["subject_being_ref"]
                    == payload["subject_being_ref"]
                    and payload["issued_at_ms"] <= event["payload"]["accepted_at_ms"]
                    and payload["not_before_ms"]
                    <= event["payload"]["accepted_at_ms"]
                    < payload["expires_at_ms"]
                ]
                if not valid_acceptances:
                    state = "offered"
                elif len(valid_acceptances) != 1:
                    state = "forked"
                else:
                    valid_revocations = []
                    for event in revocations.get(identifier, []):
                        termination = event["payload"]
                        actor = (
                            payload["grantor_being_ref"]
                            if termination["action"] == "revoke"
                            else payload["subject_being_ref"]
                        )
                        if (
                            termination["actor_being_ref"] == actor
                            and _event_ref_matches(termination["grant_ref"], grant)
                            and any(
                                _event_ref_matches(
                                    termination["acceptance_ref"], acceptance
                                )
                                for acceptance in valid_acceptances
                            )
                            and termination["revoked_at_ms"]
                            >= min(
                                acceptance["payload"]["accepted_at_ms"]
                                for acceptance in valid_acceptances
                            )
                        ):
                            valid_revocations.append(event)
                    if valid_revocations:
                        actions = {
                            event["payload"]["action"] for event in valid_revocations
                        }
                        state = (
                            "revoked+relinquished"
                            if actions == {"relinquish", "revoke"}
                            else "revoked"
                            if "revoke" in actions
                            else "relinquished"
                        )
                    elif relationship["state"] != "active":
                        state = "closed"
                    elif parent_state is not None and parent_state["state"] != "active":
                        state = parent_state["state"]
                    elif self.at_ms < payload["not_before_ms"]:
                        state = "not-yet-valid"
                    elif self.at_ms >= payload["expires_at_ms"]:
                        state = "expired"
                    else:
                        tribe = payload["tribe_ref"]
                        if tribe is not None:
                            tribe_state = self.tribes.get(tribe)
                            active_members = (
                                {
                                    being
                                    for being, member in tribe_state[
                                        "memberships"
                                    ].items()
                                    if member["state"] == "active"
                                }
                                if tribe_state is not None
                                and tribe_state["state"] == "active"
                                else set()
                            )
                            if not {
                                payload["grantor_being_ref"],
                                payload["subject_being_ref"],
                            }.issubset(active_members):
                                state = "closed"
                            else:
                                state = "active"
                        else:
                            state = "active"
                result[identifier] = {
                    "state": state,
                    "grant": grant,
                    "acceptances": valid_acceptances,
                    "parent": parent_state,
                }
                pending.remove(identifier)
                progressed = True
                break
            if not progressed:
                for identifier in pending:
                    result[identifier] = {"state": "incomplete"}
                break
        return result

    def snapshot(self, tribe_ref: str) -> VerifiedTribeSnapshot:
        tribe = self.tribes.get(tribe_ref)
        if tribe is None or tribe["state"] != "active":
            raise RelationshipStoreError("tribe_history_not_active")
        members: list[dict[str, Any]] = []
        for being_ref, membership in sorted(tribe["memberships"].items()):
            if membership["state"] != "active":
                continue
            card = self.cards.get(being_ref)
            if card is None or card["current"] is None:
                raise RelationshipStoreError("tribe_member_card_not_current")
            members.append(
                {
                    "tribe_ref": tribe_ref,
                    "principal_id": being_ref,
                    "embodiment_id": card["latest"]["payload"]["control_position"][
                        "embodiment_id"
                    ],
                    "membership_ref": membership["membership_event"]["event_id"],
                    "state": membership["state"],
                }
            )
        grants: list[dict[str, Any]] = []
        for identifier, state in sorted(self.grants.items()):
            if state["state"] != "active":
                continue
            payload = state["grant"]["payload"]
            if payload["tribe_ref"] != tribe_ref:
                continue
            for index, permission in enumerate(payload["permissions"]):
                grants.append(
                    {
                        "tribe_ref": tribe_ref,
                        "grant_ref": f"{identifier}:{index}",
                        "controller_principal_id": payload["grantor_being_ref"],
                        "grantee_principal_id": payload["subject_being_ref"],
                        "resource_ref": permission["resource_ref"],
                        "operations": permission["operations"],
                        "not_before_ms": payload["not_before_ms"],
                        "not_after_ms": payload["expires_at_ms"],
                        "parent_grant_ref": (
                            None
                            if payload["parent_grant_ref"] is None
                            else payload["parent_grant_ref"]["event_id"]
                        ),
                        "revoked": False,
                    }
                )
        lineage_core = {
            "tribe_ref": tribe_ref,
            "founder_epoch": tribe["founder_epoch"],
            "founder_being_ref": tribe["founder_being_ref"],
            "members": members,
            "grants": grants,
        }
        value = {
            "schema": TRIBE_SNAPSHOT_SCHEMA,
            "tribe_ref": tribe_ref,
            "declaration": copy.deepcopy(
                tribe["declaration"]["payload"]["declaration"]
            ),
            "founder_epoch": tribe["founder_epoch"],
            "founder_principal_id": tribe["founder_being_ref"],
            "lineage_head_ref": "dm:tribe-lineage:v1:"
            + b64url(
                hashlib.sha256(LINEAGE_DOMAIN + canonical_bytes(lineage_core)).digest()
            ),
            "verified_at_ms": self.at_ms,
            "members": members,
            "grants": grants,
        }
        return VerifiedTribeSnapshot.from_value(value, verifier=lambda _: None)

    def disclosure(
        self,
        *,
        requester_being_ref: str,
        resource_ref: str,
        operation: str,
        classification: str,
    ) -> dict[str, Any]:
        """Return one bounded success or one reason-free closed denial."""

        if not all(
            isinstance(value, str) and 1 <= len(value.encode()) <= 256
            for value in (
                requester_being_ref,
                resource_ref,
                operation,
                classification,
            )
        ):
            raise RelationshipStoreError("invalid_relationship_disclosure_request")
        matches: list[dict[str, str]] = []
        for identifier, state in sorted(self.grants.items()):
            if state["state"] != "active":
                continue
            grant = state["grant"]
            if grant["payload"]["subject_being_ref"] != requester_being_ref:
                continue
            if not any(
                permission["resource_ref"] == resource_ref
                and permission["classification"] == classification
                and operation in permission["operations"]
                for permission in grant["payload"]["permissions"]
            ):
                continue
            matches.append(
                {
                    "event_hash": grant["content_hash"],
                    "event_id": grant["event_id"],
                    "grant_id": identifier,
                }
            )
        authorization = (
            None
            if not matches
            else {
                "classification": classification,
                "grant_refs": matches,
                "operation": operation,
                "requester_being_ref": requester_being_ref,
                "resource_ref": resource_ref,
            }
        )
        return {
            "schema": "dm.relationship.disclosure/v1",
            "authorized": authorization is not None,
            "authorization": authorization,
        }

    def report(self) -> dict[str, Any]:
        return {
            "schema": "dm.relationship.history-report/v1",
            "evaluated_at_ms": self.at_ms,
            "event_count": len(self.all_events),
            "complete_event_count": len(self.complete),
            "forked_event_ids": sorted(self.forked_event_ids),
            "cards": {
                being: {
                    "current": value["current"] is not None,
                    "head_event_id": value["latest"]["event_id"],
                }
                for being, value in sorted(self.cards.items())
            },
            "relationships": {
                identifier: value["state"]
                for identifier, value in sorted(self.relationships.items())
            },
            "tribes": {
                identifier: value["state"]
                for identifier, value in sorted(self.tribes.items())
            },
            "grants": {
                identifier: value["state"]
                for identifier, value in sorted(self.grants.items())
            },
        }


__all__ = [
    "CardVerifier",
    "RelationshipAuthorityResolver",
    "RelationshipServiceContext",
    "RelationshipStore",
    "RelationshipStoreError",
    "RelationshipView",
]
