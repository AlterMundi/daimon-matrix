from __future__ import annotations

import copy
import hashlib
import json
import threading
import unittest
import uuid
from collections.abc import Mapping
from itertools import pairwise
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.identity import (
    create_binding_activation,
    create_embodiment_credential,
    create_history_binding,
    create_incarnation_authorization,
    create_revocation,
    create_synthetic_genesis_in_process,
    ed25519_public,
    key_descriptor,
    signing_descriptor,
    verify_binding_activation,
    verify_genesis,
    verify_history_binding,
    verify_successor,
    x25519_public,
)
from daimon_matrix.ledger import (
    Ledger,
    LedgerEquivocationError,
    LedgerError,
    LedgerGapError,
    LedgerStateError,
)
from daimon_matrix.weave import (
    MAX_PAGE_EVENTS,
    BeingManifest,
    BoundHistoryAuthority,
    EventSigner,
    ProvisionalAuthority,
    RootAuthority,
    WeaveProtocolError,
    create_event,
    verify_event,
)
from tools.generate_dm022_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000_000


def seed(label: str) -> bytes:
    return hashlib.sha256(f"dm-022-test:{label}".encode()).digest()


def transport(label: str, principal_id: str) -> dict[str, Any]:
    return {
        "key": key_descriptor("Ed25519", ed25519_public(seed(f"{label}-transport"))),
        "principal_id": principal_id,
        "scheme": "tribe-v1",
    }


class RootLedgerFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="dm022-ledger-")
        self.root_path = Path(self.temporary.name)
        self.root_path.chmod(0o700)
        self.root_seeds = [seed("root-a"), seed("root-b"), seed("root-c")]
        recovery = [seed("recovery-a"), seed("recovery-b"), seed("recovery-c")]
        self.genesis = create_synthetic_genesis_in_process(
            self.root_seeds,
            2,
            recovery,
            2,
            created_at_ms=NOW - 1_000,
            nonce=seed("being"),
        )
        self.state = verify_genesis(self.genesis)
        self.signing_seeds = {
            "legion": seed("legion-signing"),
            "daimonmatrix": seed("daimonmatrix-signing"),
        }
        self.credentials: dict[str, dict[str, Any]] = {}
        self.incarnations: dict[str, dict[str, Any]] = {}
        self.origins: dict[str, dict[str, str]] = {}
        rows: list[dict[str, Any]] = []
        for label in ("legion", "daimonmatrix"):
            embodiment_id = f"embodiment:{label}"
            incarnation_id = f"incarnation:{label}:0"
            body_ref = f"cluster:{label}:compaii"
            principal_id = f"compaii@{label}"
            credential = create_embodiment_credential(
                self.state,
                self.root_seeds,
                self.signing_seeds[label],
                x25519_public(seed(f"{label}-encryption")),
                embodiment_id=embodiment_id,
                body_ref=body_ref,
                purposes=["dm.we", "messages"],
                valid_from_ms=NOW - 100,
                valid_until_ms=NOW + 100_000,
                transport_principals=[transport(label, principal_id)],
            )
            incarnation = create_incarnation_authorization(
                credential,
                self.signing_seeds[label],
                incarnation_id=incarnation_id,
                incarnation_sequence=0,
                started_at_ms=NOW - 10,
            )
            self.credentials[credential["artifact_id"]] = credential
            self.incarnations[incarnation["artifact_id"]] = incarnation
            self.origins[label] = {
                "embodiment_id": embodiment_id,
                "incarnation_id": incarnation_id,
                "principal_id": principal_id,
                "body_ref": body_ref,
            }
            rows.append(
                {
                    "body_ref": body_ref,
                    "embodiment_credential_id": credential["artifact_id"],
                    "embodiment_id": embodiment_id,
                    "incarnation_authorization_id": incarnation["artifact_id"],
                    "incarnation_id": incarnation_id,
                    "status": "active",
                }
            )
        rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
        self.manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": self.state.being_ref,
                "control_head": self.state.head,
                "history_binding_id": None,
                "revision": 1,
                "embodiments": rows,
            }
        )
        self.authority = RootAuthority(
            self.manifest,
            self.state,
            self.credentials,
            self.incarnations,
        )
        self.signers = {
            label: EventSigner(
                signing_descriptor(self.signing_seeds[label])["key_id"],
                self.signing_seeds[label],
            )
            for label in self.signing_seeds
        }
        self.ledger_a = Ledger(
            self.root_path / "legion" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        self.ledger_b = Ledger(
            self.root_path / "daimonmatrix" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["daimonmatrix"],
            clock=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(
        self,
        ledger: Ledger,
        label: str,
        subject: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return ledger.append_local(
            kind="experience.observed",
            subject=subject,
            payload={"summary": subject} if payload is None else payload,
            signer=self.signers[label],
            occurred_at_ms=NOW,
        )


class KnownFeedTests(RootLedgerFixture):
    def test_same_time_pages_and_late_older_import_follow_known_intake(self) -> None:
        expected = [
            self.append(self.ledger_a, "legion", str(i))["event_id"] for i in range(9)
        ]
        cursor = None
        received: list[str] = []
        while True:
            page = self.ledger_a.known_page(cursor=cursor, limit=2)
            received.extend(row["event_id"] for row in page["events"])
            cursor = page["cursor"]
            if not page["more"]:
                break
        self.assertEqual(received, expected)
        older = self.ledger_b.append_local(
            kind="experience.observed",
            subject="late older event",
            payload={},
            signer=self.signers["daimonmatrix"],
            occurred_at_ms=NOW - 5,
        )
        self.ledger_a.ingest([older], source="remote")
        page = self.ledger_a.known_page(cursor=cursor)
        self.assertEqual(
            [row["event_id"] for row in page["events"]], [older["event_id"]]
        )
        self.assertFalse(page["more"])
        self.assertEqual(self.ledger_a.known_page(cursor="tail")["events"], [])

    def test_incomplete_event_enters_feed_only_when_promoted(self) -> None:
        parent_id = str(uuid.uuid4())
        child = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=str(uuid.uuid4()),
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=NOW - 4,
            causal_parents=[parent_id],
            kind="experience.observed",
            subject="pending",
            payload={},
        )
        self.ledger_a.ingest([child], source="remote")
        cursor = self.ledger_a.known_page(cursor=None)["cursor"]
        self.ledger_a.append_local(
            kind="experience.observed",
            subject="parent",
            payload={},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
            event_id=parent_id,
        )
        page = self.ledger_a.known_page(cursor=cursor)
        self.assertEqual(
            [row["event_id"] for row in page["events"]], [parent_id, child["event_id"]]
        )
        self.assertEqual(canonical_bytes(page["events"][1]), canonical_bytes(child))

    def remove_feed(self) -> None:
        with self.ledger_a._database() as database:
            database.executescript(
                "DROP TRIGGER feed_known_insert; DROP TRIGGER feed_known_promotion;"
                "DROP TABLE known_event_feed; DROP TABLE known_feed_state;"
            )

    def test_existing_v3_backfill_is_atomic_and_preserves_legacy_writers(self) -> None:
        expected = [
            self.append(self.ledger_a, "legion", str(i))["event_id"] for i in range(3)
        ]
        self.remove_feed()
        with self.ledger_a._database() as database:

            class FailingBootstrap:
                def __getattr__(self, name: str) -> Any:
                    return getattr(database, name)

                def execute(self, sql: str, *args: Any) -> Any:
                    if sql.startswith("INSERT INTO known_event_feed(event_id) SELECT"):
                        raise RuntimeError("synthetic interrupted backfill")
                    return database.execute(sql, *args)

            with self.assertRaisesRegex(RuntimeError, "interrupted backfill"):
                Ledger._initialize_known_feed(cast(Any, FailingBootstrap()))
            self.assertEqual(
                database.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'known_%feed%'"
                ).fetchone()[0],
                0,
            )
        first = self.ledger_a.known_page(cursor=None)
        self.assertEqual([row["event_id"] for row in first["events"]], expected)
        older = self.append(self.ledger_b, "daimonmatrix", "legacy writer")
        # This is the INSERT/status UPDATE used by pre-feed schema-v3 writers;
        # SQLite triggers populate the index without requiring new SDK code.
        with self.ledger_a._database() as database:
            self.ledger_a._insert(database, older, source="legacy", status="incomplete")
            database.execute(
                "UPDATE events SET status='known' WHERE event_id=?",
                (older["event_id"],),
            )
        self.assertEqual(
            self.ledger_a.known_page(cursor=first["cursor"])["events"], [older]
        )
        complete = self.ledger_a.known_page(cursor=None)
        self.assertEqual(
            [row["event_id"] for row in complete["events"]],
            [*expected, older["event_id"]],
        )
        self.ledger_a.initialize()
        self.assertEqual(
            self.ledger_a.known_page(cursor=complete["cursor"])["events"], []
        )
        with self.ledger_a._database() as database:
            self.assertEqual(
                database.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
                "3",
            )

    def test_cursor_refuses_other_store_and_restored_earlier_boundary(self) -> None:
        self.append(self.ledger_a, "legion", "one")
        original = self.ledger_a.path.read_bytes()
        self.append(self.ledger_a, "legion", "two")
        cursor = self.ledger_a.known_page(cursor=None)["cursor"]
        with self.assertRaisesRegex(LedgerError, "invalid_known_cursor"):
            self.ledger_b.known_page(cursor=cursor)
        self.ledger_a.path.write_bytes(original)
        with self.assertRaisesRegex(LedgerError, "invalid_known_cursor"):
            self.ledger_a.known_page(cursor=cursor)
        for invalid in ("garbage", "", 3, {"position": 1}):
            with self.assertRaisesRegex(LedgerError, "invalid_known_cursor"):
                self.ledger_a.known_page(cursor=cast(Any, invalid))


class AuthorizationAndCompatibilityTests(RootLedgerFixture):
    def test_root_manifest_and_event_match_closed_schemas(self) -> None:
        event = self.append(self.ledger_a, "legion", "schema")
        for relative, value in (
            ("schemas/weave/v1/root-manifest.schema.json", self.manifest.value),
            ("schemas/weave/v1/event.schema.json", event),
        ):
            schema = json.loads((ROOT / relative).read_bytes())
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

    def test_root_authority_binds_body_incarnation_principal_and_signer(self) -> None:
        event = self.append(self.ledger_a, "legion", "authorized")
        verify_event(event, self.authority)

        mutations = [
            ("body_ref", "cluster:attacker:body"),
            ("principal_id", "compaii@attacker"),
            ("incarnation_id", "incarnation:attacker:0"),
        ]
        for field, replacement in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(event)
                changed["origin"][field] = replacement
                with self.assertRaises(WeaveProtocolError):
                    verify_event(changed, self.authority)

        wrong_signer = copy.deepcopy(event)
        wrong_signer["signature"]["kid"] = self.signers["daimonmatrix"].key_id
        with self.assertRaises(WeaveProtocolError):
            verify_event(wrong_signer, self.authority)

        malformed_signature = copy.deepcopy(event)
        malformed_signature["signature"]["value"] = "not-base64url"
        with self.assertRaisesRegex(WeaveProtocolError, "invalid_signature"):
            verify_event(malformed_signature, self.authority)

        revised_manifest = BeingManifest.from_value(
            {**self.manifest.value, "revision": 2}
        )
        revised_authority = RootAuthority(
            revised_manifest,
            self.state,
            self.credentials,
            self.incarnations,
        )
        with self.assertRaisesRegex(WeaveProtocolError, "manifest_hash_mismatch"):
            verify_event(event, revised_authority)

    def test_revoked_later_incarnation_cannot_authorize_events(self) -> None:
        credential = next(
            value
            for value in self.credentials.values()
            if value["body"]["embodiment_id"] == "embodiment:legion"
        )
        later = create_incarnation_authorization(
            credential,
            self.signing_seeds["legion"],
            incarnation_id="incarnation:legion:1",
            incarnation_sequence=1,
            started_at_ms=NOW,
        )
        revocation = create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id="embodiment:legion",
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked_state = verify_successor(revocation, self.state)
        row = {
            "body_ref": "cluster:legion:compaii",
            "embodiment_credential_id": credential["artifact_id"],
            "embodiment_id": "embodiment:legion",
            "incarnation_authorization_id": later["artifact_id"],
            "incarnation_id": "incarnation:legion:1",
            "status": "active",
        }
        manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": revoked_state.being_ref,
                "control_head": revoked_state.head,
                "history_binding_id": None,
                "revision": 2,
                "embodiments": [row],
            }
        )
        with self.assertRaisesRegex(WeaveProtocolError, "invalid_origin_authorization"):
            RootAuthority(
                manifest,
                revoked_state,
                {credential["artifact_id"]: credential},
                {later["artifact_id"]: later},
            )

    def test_every_manifest_member_is_verified_before_use(self) -> None:
        rows = copy.deepcopy(self.manifest.value["embodiments"])
        rows[0]["incarnation_authorization_id"] = "dm:identity:v1:" + "A" * 43
        manifest = BeingManifest.from_value(
            {**self.manifest.value, "embodiments": rows}
        )
        with self.assertRaisesRegex(WeaveProtocolError, "missing_origin_authorization"):
            RootAuthority(
                manifest,
                self.state,
                self.credentials,
                self.incarnations,
            )

    def test_published_provisional_vector_remains_byte_compatible(self) -> None:
        vector_root = ROOT / "vectors" / "weave" / "v1"
        index = json.loads((vector_root / "index.json").read_bytes())
        manifest = BeingManifest.from_value(
            json.loads((vector_root / index["manifest"]).read_bytes())
        )
        authority = ProvisionalAuthority(manifest, index["public_keys"])
        event = json.loads((vector_root / index["valid_events"][0]).read_bytes())
        verified = verify_event(event, authority)
        self.assertEqual(verified["content_hash"], event["content_hash"])
        self.assertEqual(manifest.digest, index["manifest_hash"])

    def test_signed_binding_preserves_provisional_bytes_and_blocks_downgrade(
        self,
    ) -> None:
        vector_root = ROOT / "vectors" / "weave" / "v1"
        index = json.loads((vector_root / "index.json").read_bytes())
        provisional_manifest = BeingManifest.from_value(
            json.loads((vector_root / index["manifest"]).read_bytes())
        )
        provisional = ProvisionalAuthority(provisional_manifest, index["public_keys"])
        historical_event = json.loads(
            (vector_root / index["valid_events"][0]).read_bytes()
        )
        head = {
            "content_hash": historical_event["content_hash"],
            "event_id": historical_event["event_id"],
            "incarnation_id": historical_event["origin"]["incarnation_id"],
            "origin_embodiment_id": historical_event["origin"]["embodiment_id"],
            "sequence": historical_event["sequence"],
            "signer_key_id": historical_event["signature"]["kid"],
        }
        binding = create_history_binding(
            self.state,
            self.root_seeds,
            provisional_being_ref=provisional_manifest.being_ref,
            manifest_bytes=canonical_bytes(provisional_manifest.value),
            manifest_revision=1,
            accepted_heads=[head],
        )
        verify_history_binding(
            binding,
            self.state,
            manifest_bytes=canonical_bytes(provisional_manifest.value),
            manifest_revision=1,
            accepted_heads=[head],
            verify_head=lambda candidate: candidate == head,
        )
        activation = create_binding_activation(self.state, self.root_seeds, binding)
        activated_state = verify_binding_activation(activation, binding, self.state)
        root_manifest = BeingManifest.from_value(
            {
                **self.manifest.value,
                "history_binding_id": binding["artifact_id"],
            }
        )
        active = RootAuthority(
            root_manifest,
            activated_state,
            self.credentials,
            self.incarnations,
        )
        authority = BoundHistoryAuthority(
            active,
            provisional,
            binding,
            {historical_event["event_id"]: historical_event},
        )
        ledger = Ledger(
            self.root_path / "bound" / "ledger.sqlite",
            authority=authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )

        before = canonical_bytes(historical_event)
        ledger.ingest([historical_event], source="provisional-import")
        current = ledger.append_local(
            kind="experience.observed",
            subject="root-bound",
            payload={"summary": "continued without rewrite"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )

        events = {event["event_id"]: event for event in ledger.events()}
        self.assertEqual(canonical_bytes(events[historical_event["event_id"]]), before)
        self.assertEqual(current["being_ref"], activated_state.being_ref)
        self.assertEqual(
            {event["manifest_hash"] for event in events.values()},
            {provisional_manifest.digest, root_manifest.digest},
        )

        unbound = copy.deepcopy(historical_event)
        unbound["event_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(WeaveProtocolError, "unbound_historical_event"):
            verify_event(unbound, authority)
        with self.assertRaisesRegex(Exception, "metadata_mismatch"):
            Ledger(
                ledger.path,
                authority=provisional,
                local_origin=historical_event["origin"],
            ).initialize()


class LedgerBehaviorTests(RootLedgerFixture):
    def test_partition_preview_pull_restart_resume_and_local_adoption(self) -> None:
        local = self.append(self.ledger_a, "legion", "legion-only")
        remote_first = self.append(self.ledger_b, "daimonmatrix", "remote-one")
        remote_second = self.append(self.ledger_b, "daimonmatrix", "remote-two")

        first_page = self.ledger_b.delta([], limit=1)
        before = self.ledger_a.events()
        self.assertEqual(self.ledger_a.preview(first_page)["missing"], 1)
        self.assertEqual(self.ledger_a.events(), before)
        self.assertEqual(
            self.ledger_a.ingest(first_page, source="compaii@daimonmatrix")["missing"],
            1,
        )

        restarted = Ledger(
            self.ledger_a.path,
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW + 1,
        )
        restarted.ingest(
            self.ledger_b.delta(restarted.heads()), source="compaii@daimonmatrix"
        )
        self.assertEqual(
            restarted.ingest(self.ledger_b.delta([]), source="compaii@daimonmatrix")[
                "missing"
            ],
            0,
        )
        self.assertEqual(
            restarted.peer_cursors("compaii@daimonmatrix")[0]["sequence"], 2
        )

        self.ledger_b.ingest(restarted.delta([]), source="compaii@legion")
        self.assertEqual(
            {event["event_id"] for event in restarted.events()},
            {event["event_id"] for event in self.ledger_b.events()},
        )
        self.assertEqual(
            {event["event_id"] for event in restarted.events()},
            {local["event_id"], remote_first["event_id"], remote_second["event_id"]},
        )

        decision = restarted.append_local(
            kind="adoption.decided",
            subject="remote-two",
            payload={
                "target_event_id": remote_second["event_id"],
                "decision": "adopt",
                "reason": "accepted locally",
            },
            signer=self.signers["legion"],
            causal_parents=[remote_second["event_id"]],
            occurred_at_ms=NOW + 2,
        )
        states = {item["event_id"]: item["state"] for item in restarted.diff()}
        self.assertEqual(states[remote_second["event_id"]], "adopted")
        peer_states = {item["event_id"]: item["state"] for item in self.ledger_b.diff()}
        self.assertEqual(peer_states[remote_second["event_id"]], "pending")

        restarted.append_local(
            kind="adoption.decided",
            subject="remote-two",
            payload={
                "target_event_id": remote_second["event_id"],
                "decision": "revert",
                "reason": "changed locally",
            },
            signer=self.signers["legion"],
            causal_parents=[remote_second["event_id"]],
            supersedes=decision["event_id"],
            occurred_at_ms=NOW + 3,
        )
        self.assertEqual(
            {item["event_id"]: item["state"] for item in restarted.diff()}[
                remote_second["event_id"]
            ],
            "reverted",
        )

    def test_gap_invalid_page_and_equivocation_are_atomic(self) -> None:
        first = self.append(self.ledger_b, "daimonmatrix", "one")
        second = self.append(self.ledger_b, "daimonmatrix", "two")
        with self.assertRaises(LedgerGapError):
            self.ledger_a.ingest([second], source="compaii@daimonmatrix")
        self.assertEqual(self.ledger_a.events(), [])
        self.assertEqual(self.ledger_a.peer_sync_states()[0]["state"], "gap")

        invalid = copy.deepcopy(second)
        invalid["payload"]["summary"] = "tampered"
        with self.assertRaises(WeaveProtocolError):
            self.ledger_a.ingest([first, invalid], source="compaii@daimonmatrix")
        self.assertEqual(self.ledger_a.events(), [])

        self.ledger_a.ingest([first], source="compaii@daimonmatrix")
        same_id = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=first["event_id"],
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=NOW,
            causal_parents=[],
            kind="experience.observed",
            subject="same-id-conflict",
            payload={"summary": "different signed content under the same ID"},
        )
        with self.assertRaises(LedgerEquivocationError):
            self.ledger_a.ingest([same_id], source="same-id-attacker")

        conflict = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=str(uuid.uuid4()),
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=NOW,
            causal_parents=[],
            kind="experience.observed",
            subject="conflict",
            payload={"summary": "different valid bytes"},
        )
        with self.assertRaises(LedgerEquivocationError):
            self.ledger_a.ingest([conflict], source="compaii@daimonmatrix")
        self.assertEqual(
            [event["event_id"] for event in self.ledger_a.events()], [first["event_id"]]
        )
        self.assertEqual(len(self.ledger_a.equivocations()), 2)
        self.assertEqual(
            {row["peer_id"]: row["state"] for row in self.ledger_a.peer_sync_states()},
            {
                "compaii@daimonmatrix": "quarantined",
                "same-id-attacker": "quarantined",
            },
        )

        conflicting_head = copy.deepcopy(self.ledger_a.heads())
        conflicting_head[0]["tip_hash"] = "0" * 64
        with self.assertRaisesRegex(LedgerEquivocationError, "origin_equivocation"):
            self.ledger_a.delta(conflicting_head)

    def test_causal_missing_is_incomplete_then_promotes_without_rewrite(self) -> None:
        parent_id = str(uuid.uuid4())
        dependent = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=str(uuid.uuid4()),
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=NOW,
            causal_parents=[parent_id],
            kind="experience.observed",
            subject="dependent",
            payload={"summary": "waits for parent"},
        )
        self.ledger_a.ingest([dependent], source="compaii@daimonmatrix")
        self.assertEqual(self.ledger_a.incomplete_count(), 1)
        self.assertEqual(self.ledger_a.diff(), [])

        successor = create_event(
            self.authority,
            self.origins["daimonmatrix"],
            self.signers["daimonmatrix"],
            event_id=str(uuid.uuid4()),
            sequence=2,
            previous_event_id=dependent["event_id"],
            occurred_at_ms=NOW + 1,
            causal_parents=[],
            kind="experience.observed",
            subject="successor",
            payload={"summary": "must wait for its incomplete predecessor"},
        )
        self.ledger_a.ingest([successor], source="compaii@daimonmatrix")
        self.assertEqual(self.ledger_a.incomplete_count(), 2)
        self.assertEqual(self.ledger_a.diff(), [])

        parent = self.ledger_a.append_local(
            kind="experience.observed",
            subject="parent",
            payload={"summary": "causal parent"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
            event_id=parent_id,
        )
        self.assertEqual(self.ledger_a.incomplete_count(), 0)
        self.assertEqual(
            {event["event_id"] for event in self.ledger_a.events()},
            {parent["event_id"], dependent["event_id"], successor["event_id"]},
        )
        self.assertEqual(len(self.ledger_a.diff()), 3)

    def test_oversize_event_and_page_reject_without_partial_state(self) -> None:
        with self.assertRaisesRegex(WeaveProtocolError, "event_too_large"):
            self.append(
                self.ledger_b,
                "daimonmatrix",
                "oversize",
                payload={f"field_{index}": "x" * 65_000 for index in range(5)},
            )
        self.assertEqual(self.ledger_b.events(), [])

        event = self.append(self.ledger_b, "daimonmatrix", "bounded")
        with self.assertRaisesRegex(WeaveProtocolError, "delta_page_too_large"):
            self.ledger_a.ingest(
                [event] * (MAX_PAGE_EVENTS + 1),
                source="compaii@daimonmatrix",
            )
        self.assertEqual(self.ledger_a.events(), [])

    def test_concurrent_writers_allocate_one_contiguous_chain(self) -> None:
        self.ledger_a.initialize()
        barrier = threading.Barrier(8)
        events: list[dict[str, Any]] = []
        errors: list[BaseException] = []

        def append(index: int) -> None:
            barrier.wait()
            try:
                events.append(
                    self.ledger_a.append_local(
                        kind="experience.observed",
                        subject=f"concurrent-{index}",
                        payload={"index": index},
                        signer=self.signers["legion"],
                        occurred_at_ms=NOW + index,
                    )
                )
            except BaseException as exception:
                errors.append(exception)

        threads = [threading.Thread(target=append, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(
            sorted(event["sequence"] for event in events), list(range(1, 9))
        )
        stored = self.ledger_a.events()
        self.assertEqual([event["sequence"] for event in stored], list(range(1, 9)))
        for prior, current in pairwise(stored):
            self.assertEqual(current["previous_event_id"], prior["event_id"])

    def test_secret_payload_and_unsafe_filesystem_fail_closed(self) -> None:
        with self.assertRaisesRegex(WeaveProtocolError, "secret_value_forbidden"):
            self.append(
                self.ledger_a,
                "legion",
                "secret",
                payload={"api_token": "must-not-enter-ledger"},
            )
        with self.assertRaisesRegex(WeaveProtocolError, "invalid_payload_value"):
            self.append(
                self.ledger_a,
                "legion",
                "float",
                payload={"value": 1.5},
            )
        self.assertEqual(self.ledger_a.events(), [])

        self.ledger_a.initialize()
        self.ledger_a.path.chmod(0o644)
        with self.assertRaisesRegex(Exception, "owner_only"):
            self.ledger_a.events()

        target = self.root_path / "symlink-target"
        target.mkdir(mode=0o700)
        link = self.root_path / "symlink-parent"
        link.symlink_to(target, target_is_directory=True)
        unsafe = Ledger(
            link / "created-through-link" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["legion"],
        )
        with self.assertRaisesRegex(LedgerStateError, "ancestor_symlink"):
            unsafe.initialize()
        self.assertFalse((target / "created-through-link").exists())


class DM022VectorTests(unittest.TestCase):
    def _load_authority(
        self,
    ) -> tuple[Path, RootAuthority, dict[str, Any], Mapping[str, Any]]:
        vector_root = ROOT / "vectors" / "weave" / "v1" / "root-bound"
        index = cast(
            dict[str, Any], json.loads((vector_root / "index.json").read_bytes())
        )

        def identity(name: str) -> dict[str, Any]:
            return cast(
                dict[str, Any],
                json.loads((vector_root / index["identity"][name]).read_bytes()),
            )

        genesis = identity("genesis")
        credential = identity("embodiment_credential")
        incarnation = identity("incarnation_authorization")
        manifest = BeingManifest.from_value(
            json.loads((vector_root / index["manifest"]).read_bytes())
        )
        authority = RootAuthority(
            manifest,
            verify_genesis(genesis),
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
        return vector_root, authority, index, manifest.value

    def test_public_root_bound_vectors_validate_and_tamper_fails(self) -> None:
        vector_root, authority, index, manifest = self._load_authority()
        event = json.loads((vector_root / index["valid_event"]).read_bytes())
        negative = json.loads((vector_root / index["negative_event"]).read_bytes())
        verify_event(event, authority)
        with self.assertRaisesRegex(WeaveProtocolError, "content_hash_mismatch"):
            verify_event(negative, authority)
        for relative, value in (
            ("schemas/weave/v1/root-manifest.schema.json", manifest),
            ("schemas/weave/v1/event.schema.json", event),
        ):
            Draft202012Validator(json.loads((ROOT / relative).read_bytes())).validate(
                value
            )

    def test_root_bound_vector_regeneration_is_byte_identical(self) -> None:
        expected = ROOT / "vectors" / "weave" / "v1" / "root-bound"
        with TemporaryDirectory(prefix="dm022-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected_files = sorted(
                path.relative_to(expected) for path in expected.rglob("*.json")
            )
            generated_files = sorted(
                path.relative_to(generated) for path in generated.rglob("*.json")
            )
            self.assertEqual(generated_files, expected_files)
            for relative in expected_files:
                self.assertEqual(
                    (generated / relative).read_bytes(),
                    (expected / relative).read_bytes(),
                )


if __name__ == "__main__":
    unittest.main()
