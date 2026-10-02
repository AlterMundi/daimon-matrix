"""Migration must preserve accepted history and exact public-operation replay."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from typing import Any
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.communication import (
    CommunicationError,
    CommunicationStore,
    SyntheticRouteProvider,
    dispatch_attempt,
    select_persisted_schema,
)
from tests.test_dm022_ledger import NOW
from tests.test_dm052_communication import LogicalCommunicationFixture, identifier


class HistoricalMigrationTests(LogicalCommunicationFixture):
    def migrate_and_reopen(self) -> None:
        self.store.upgrade_receipts_v2()
        self.store.upgrade_legs_v3()
        self.store = CommunicationStore(self.ledger_a, clock=self.store.clock)
        select_persisted_schema(self.store, self.ledger_a)
        self.store.initialize()

    def test_accepted_attempt_retains_exact_document_and_retry(self) -> None:
        message, resolution, accepted = self.append_message(
            [self.target("embodiment:legion")]
        )
        attempt = self.attempt(accepted["legs"][0]["leg_id"], 1)
        original = self.store.record_attempt(attempt)
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            before = database.execute(
                "SELECT attempt_json, attempt_hash FROM communication_attempts"
            ).fetchall()
        self.migrate_and_reopen()
        self.assertEqual(self.store.record_attempt(attempt), original)
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(
                database.execute(
                    "SELECT attempt_json, attempt_hash FROM communication_attempts"
                ).fetchall(),
                before,
            )
        replay = self.store.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        self.assertEqual(len(replay["legs"]), 1)
        self.assertEqual(replay["legs"][0]["sequence"], accepted["legs"][0]["sequence"])

    def test_terminal_receipt_replays_and_preserves_original_projection(self) -> None:
        message, _, accepted = self.append_message([self.target("embodiment:legion")])
        receipt = self.receipt(accepted, "embodiment:legion", "delivered")
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            before = database.execute(
                "SELECT receipt_json FROM communication_receipts"
            ).fetchall()
        self.migrate_and_reopen()
        self.assertTrue(
            self.store.result(message["event_id"], require_terminal=True)["terminal"]
        )
        self.assertTrue(self.store.record_receipt(receipt["event_id"])["terminal"])
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(
                database.execute(
                    "SELECT receipt_json FROM communication_receipts"
                ).fetchall(),
                before,
            )

    def test_cached_page_is_exact_after_migration(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        arguments: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=1,
        )
        before = self.store.page(**arguments)
        self.migrate_and_reopen()
        self.assertEqual(self.store.page(**arguments), before)

    def test_cached_claim_is_exact_after_migration(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        arguments: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="consumer:migration",
            claim_id=identifier(69_000_000, 1),
            lease_until_ms=NOW + 1000,
            limit=1,
        )
        before = self.store.claim(**arguments)
        self.migrate_and_reopen()
        self.assertEqual(self.store.claim(**arguments), before)

    def test_cursor_continuation_preserves_cutoff_and_cached_pages(self) -> None:
        messages = [
            self.append_message([self.target("embodiment:legion")])[0] for _ in range(8)
        ]
        first_request: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="migration:pages",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=3,
        )
        first = self.store.page(**first_request)
        second_request = {
            **first_request,
            "request_id": identifier(70_000_000, 2),
            "cursor": first["next_cursor"],
        }
        second = self.store.page(**second_request)
        self.migrate_and_reopen()
        self.append_message([self.target("embodiment:legion")])
        self.assertEqual(self.store.page(**first_request), first)
        self.assertEqual(self.store.page(**second_request), second)
        third = self.store.page(
            **{
                **first_request,
                "request_id": identifier(70_000_000, 3),
                "cursor": second["next_cursor"],
            }
        )
        self.assertIsNone(third["next_cursor"])
        self.assertEqual(third["snapshot_highwater"], first["snapshot_highwater"])
        self.assertEqual(
            [
                item["message_id"]
                for page in (first, second, third)
                for item in page["items"]
            ],
            [message["event_id"] for message in messages],
        )

    def test_accepted_snapshot_stays_exact_after_delivery_and_compaction(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        request: dict[str, Any] = dict(
            recipient_id="embodiment:legion",
            consumer_id="migration:compacted",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=1,
        )
        page = self.store.page(**request)
        self.receipt(accepted, "embodiment:legion", "delivered")
        sequence = accepted["legs"][0]["sequence"]
        self.store.advance_consumer(
            recipient_id=request["recipient_id"],
            consumer_id=request["consumer_id"],
            sequence=sequence,
        )
        self.store.compact(
            recipient_id=request["recipient_id"], through_sequence=sequence
        )
        self.migrate_and_reopen()
        self.assertEqual(self.store.page(**request), page)
        self.assertEqual(
            self.store.leg(accepted["legs"][0]["leg_id"])["state"], "delivered"
        )
        with self.assertRaisesRegex(CommunicationError, "semantic_leg_not_accepted"):
            self.store.record_attempt(self.attempt(accepted["legs"][0]["leg_id"], 9))

    def test_old_leg_remains_addressable(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        before = accepted["legs"][0]
        self.migrate_and_reopen()
        after = self.store.leg(before["leg_id"])
        self.assertEqual(after["message_id"], before["message_id"])
        self.assertEqual(
            after["receipt_origin_embodiment_id"],
            before["receipt_origin_embodiment_id"],
        )
        self.assertEqual(after["sequence"], before["sequence"])

    def test_acknowledged_attempt_retains_exact_retry(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        attempt = self.attempt(accepted["legs"][0]["leg_id"], 4)
        provider = SyntheticRouteProvider(provider_ref="route:fake-direct")
        acknowledgement = dispatch_attempt(self.store, provider, attempt)
        self.assertEqual(acknowledgement["state"], "route-acked")
        before = self.store.record_attempt(attempt)
        self.migrate_and_reopen()
        self.assertEqual(self.store.record_attempt(attempt), before)

    def test_corrupt_source_cannot_commit_a_schema_upgrade(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        self.store.record_attempt(self.attempt(accepted["legs"][0]["leg_id"], 1))
        self.store.upgrade_receipts_v2()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_attempts SET attempt_hash=?", ("0" * 64,)
            )
            database.commit()
            before = tuple(database.iterdump())
        with self.assertRaisesRegex(CommunicationError, "route_attempt_store_corrupt"):
            self.store.upgrade_legs_v3()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(tuple(database.iterdump()), before)

    def test_alias_is_lookup_and_exact_retry_only(self) -> None:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        old_id = accepted["legs"][0]["leg_id"]
        original = self.attempt(old_id, 1)
        self.store.record_attempt(original)
        self.migrate_and_reopen()
        with self.assertRaisesRegex(
            CommunicationError, "historical_leg_requires_exact_retry"
        ):
            self.store.record_attempt(self.attempt(old_id, 2))
        changed = {**original, "deadline_ms": NOW + 5000}
        with self.assertRaisesRegex(CommunicationError, "route_attempt_conflict"):
            self.store.record_attempt(changed)
        canonical = self.store.leg(old_id)["leg_id"]
        self.assertNotEqual(canonical, old_id)
        self.store.record_attempt(self.attempt(canonical, 3))

    def test_missing_alias_fails_on_reopen(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        self.migrate_and_reopen()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("DELETE FROM communication_leg_aliases")
            database.commit()
        with self.assertRaisesRegex(
            CommunicationError, "communication_aliases_corrupt"
        ):
            self.store.initialize()

    def test_alias_cannot_be_retargeted_to_a_new_body(self) -> None:
        _, _, old = self.append_message([self.target("embodiment:legion")])
        self.migrate_and_reopen()
        _, _, new = self.append_message([self.target("embodiment:daimonmatrix")])
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_leg_aliases SET canonical_id=?",
                (new["legs"][0]["leg_id"],),
            )
            database.commit()
        with self.assertRaisesRegex(
            CommunicationError, "communication_aliases_corrupt"
        ):
            self.store.leg(old["legs"][0]["leg_id"])

    def test_corrupt_cached_history_prevents_schema_commit(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        response = self.store.page(
            recipient_id="embodiment:legion",
            consumer_id="reader",
            request_id=identifier(70_000_000, 1),
            cursor=None,
            limit=1,
        )
        self.store.upgrade_receipts_v2()
        response["items"][0]["sequence"] += 1
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_page_requests SET response_json=?",
                (canonical_bytes(response),),
            )
            database.commit()
            before = tuple(database.iterdump())
        with self.assertRaisesRegex(CommunicationError, "page_state_corrupt"):
            self.store.upgrade_legs_v3()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(tuple(database.iterdump()), before)

    def test_conflict_evidence_and_link_survive(self) -> None:
        old_id, before = self.delivery_conflict()
        self.migrate_and_reopen()
        after = self.store.conflicts()[0]
        self.assertEqual(after["evidence"], before["evidence"])
        self.assertEqual(after["conflict_hash"], before["conflict_hash"])
        self.assertEqual(self.store.leg(old_id)["state"], "quarantined")
        self.assertEqual(after["leg_id"], self.store.leg(old_id)["leg_id"])

    def delivery_conflict(self) -> tuple[str, dict[str, Any]]:
        _, _, accepted = self.append_message([self.target("embodiment:legion")])
        old_id = accepted["legs"][0]["leg_id"]
        attempt = self.attempt(old_id, 3)
        self.store.record_attempt(attempt)
        arguments = dict(
            attempt_id=attempt["attempt_id"], delivery_id=identifier(60_000_000, 3)
        )
        self.store.record_delivery(**arguments, envelope_hash="a" * 64)
        with self.assertRaisesRegex(CommunicationError, "delivery_id_conflict"):
            self.store.record_delivery(**arguments, envelope_hash="b" * 64)
        return old_id, self.store.conflicts()[0]

    def test_dangling_conflict_prevents_schema_commit(self) -> None:
        self.delivery_conflict()
        self.store.upgrade_receipts_v2()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("UPDATE communication_conflicts SET leg_id='bogus-leg'")
            database.commit()
            before = tuple(database.iterdump())
        with self.assertRaisesRegex(
            CommunicationError, "communication_conflict_corrupt"
        ):
            self.store.upgrade_legs_v3()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(tuple(database.iterdump()), before)

    def test_changed_conflict_evidence_hash_refuses(self) -> None:
        self.delivery_conflict()
        self.migrate_and_reopen()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_conflicts SET conflict_hash=?", ("0" * 64,)
            )
            database.commit()
        with self.assertRaisesRegex(
            CommunicationError, "communication_conflict_corrupt"
        ):
            self.store.conflicts()

    def test_every_conflicting_leg_must_remain_quarantined(self) -> None:
        _, _, first = self.append_message([self.target("embodiment:legion")])
        _, _, second = self.append_message([self.target("embodiment:daimonmatrix")])
        attempts = [
            self.attempt(result["legs"][0]["leg_id"], index)
            for index, result in enumerate((first, second), start=1)
        ]
        for attempt in attempts:
            self.store.record_attempt(attempt)
        delivery_id = identifier(60_000_000, 9)
        self.store.record_delivery(
            attempt_id=attempts[0]["attempt_id"],
            delivery_id=delivery_id,
            envelope_hash="a" * 64,
        )
        with self.assertRaisesRegex(CommunicationError, "delivery_id_conflict"):
            self.store.record_delivery(
                attempt_id=attempts[1]["attempt_id"],
                delivery_id=delivery_id,
                envelope_hash="a" * 64,
            )
        self.migrate_and_reopen()
        canonical = self.store.leg(first["legs"][0]["leg_id"])["leg_id"]
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE communication_legs SET state='accepted' WHERE leg_id=?",
                (canonical,),
            )
            database.commit()
        with self.assertRaisesRegex(
            CommunicationError, "communication_conflict_corrupt"
        ):
            self.store.leg(first["legs"][0]["leg_id"])
        with self.assertRaisesRegex(
            CommunicationError, "communication_conflict_corrupt"
        ):
            self.store.record_attempt(self.attempt(canonical, 6))

    def test_old_schema_reader_refuses_successor(self) -> None:
        self.migrate_and_reopen()
        old = CommunicationStore(self.ledger_a, receipts_v2=True, legs_v3=True)
        with self.assertRaisesRegex(
            CommunicationError, "communication_metadata_mismatch"
        ):
            old.initialize()

    def test_healthy_original_v3_remains_readable_without_aliases(self) -> None:
        # With no legacy rows this reconstructs the original canonical schema3:
        # exact same legs/table references, no historical compatibility catalogs.
        self.migrate_and_reopen()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("DROP TABLE communication_leg_aliases")
            database.execute("DROP TABLE communication_leg_migration")
            database.execute(
                "UPDATE communication_meta SET value='3' WHERE key='schema_version'"
            )
            database.commit()
        self.store = CommunicationStore(self.ledger_a, clock=lambda: NOW)
        select_persisted_schema(self.store, self.ledger_a)
        message, _, accepted = self.append_message([self.target("embodiment:legion")])
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            before = tuple(database.iterdump())
        select_persisted_schema(self.store, self.ledger_a)
        self.assertEqual(self.store.result(message["event_id"]), accepted)
        self.assertFalse(self.store.historical_legs)
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(tuple(database.iterdump()), before)

    def test_candidate_validation_failure_rolls_back_complete_transition(self) -> None:
        self.append_message([self.target("embodiment:legion")])
        self.store.upgrade_receipts_v2()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            before = tuple(database.iterdump())
        anchor = self.store.anchor_path.read_bytes()
        validate = CommunicationStore._validate_store

        def fail_candidate(
            store: CommunicationStore, database: sqlite3.Connection
        ) -> None:
            validate(store, database)
            if store.historical_legs:
                raise CommunicationError("injected_candidate_validation_failure")

        with (
            patch.object(CommunicationStore, "_validate_store", fail_candidate),
            self.assertRaisesRegex(
                CommunicationError, "injected_candidate_validation_failure"
            ),
        ):
            self.store.upgrade_legs_v3()
        self.assertFalse(self.store.historical_legs)
        self.assertFalse(self.store.legs_v3)
        self.assertEqual(self.store.anchor_path.read_bytes(), anchor)
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            self.assertEqual(tuple(database.iterdump()), before)
