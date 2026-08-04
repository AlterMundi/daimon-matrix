from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.identity import create_incarnation_authorization
from daimon_matrix.ledger import SCHEMA_VERSION, Ledger, LedgerError
from daimon_matrix.projections import (
    PROJECTION_DOMAIN,
    ProjectionEngine,
    ProjectionError,
)
from daimon_matrix.sync import (
    DELTA_DOMAIN,
    SyncEngine,
    SyncProtocolError,
    peer_id,
    validate_heads_document,
    validate_receipt,
)
from daimon_matrix.weave import (
    BeingManifest,
    ProvisionalAuthority,
    RootAuthority,
    create_event,
)
from tests.test_dm022_ledger import NOW, RootLedgerFixture

ROOT = Path(__file__).resolve().parents[1]


def request_id(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


class SyncTransactionTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.sync_a = SyncEngine(self.ledger_a)
        self.sync_b = SyncEngine(self.ledger_b)

    def test_sync_refuses_unbound_provisional_authority(self) -> None:
        embodiment_id = "embodiment:00000000-0000-4000-8000-000000000101"
        manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v1",
                "being_ref": "being:00000000-0000-4000-8000-000000000100",
                "revision": 1,
                "embodiments": [
                    {
                        "embodiment_id": embodiment_id,
                        "principal_id": "compaii@provisional",
                        "body_ref": "cluster:provisional:compaii",
                        "status": "active",
                    }
                ],
            }
        )
        ledger = Ledger(
            self.root_path / "provisional" / "ledger.sqlite",
            authority=ProvisionalAuthority(manifest, {}),
            local_origin={
                "embodiment_id": embodiment_id,
                "incarnation_id": ("incarnation:00000000-0000-4000-8000-000000000102"),
                "principal_id": "compaii@provisional",
                "body_ref": "cluster:provisional:compaii",
            },
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(SyncProtocolError, "sync_requires_root_authority"):
            SyncEngine(ledger)

    def test_partition_resume_and_exact_request_and_receipt_replay(self) -> None:
        local_a = self.append(self.ledger_a, "legion", "a-one")
        remote = [
            self.append(self.ledger_b, "daimonmatrix", "b-one"),
            self.append(self.ledger_b, "daimonmatrix", "b-two"),
        ]
        request = self.sync_a.request(request_id=request_id(1), limit=1)
        page = self.sync_b.serve(request)
        self.assertTrue(page["more"])
        self.assertEqual(len(page["events"]), 1)
        self.assertEqual(
            canonical_bytes(self.sync_b.serve(request)), canonical_bytes(page)
        )

        late = self.append(self.ledger_b, "daimonmatrix", "b-after-frozen-page")
        self.assertEqual(
            canonical_bytes(self.sync_b.serve(request)), canonical_bytes(page)
        )

        receipt = self.sync_a.pull(page)
        self.assertEqual(receipt["inserted"], 1)
        self.assertEqual(receipt["replayed"], 0)
        self.assertEqual(
            canonical_bytes(self.sync_a.pull(page)), canonical_bytes(receipt)
        )
        restarted_a = SyncEngine(
            Ledger(
                self.ledger_a.path,
                authority=self.authority,
                local_origin=self.origins["legion"],
                clock=lambda: NOW,
            )
        )
        restarted_b = SyncEngine(
            Ledger(
                self.ledger_b.path,
                authority=self.authority,
                local_origin=self.origins["daimonmatrix"],
                clock=lambda: NOW,
            )
        )
        self.assertEqual(
            canonical_bytes(restarted_a.pull(page)), canonical_bytes(receipt)
        )
        self.assertEqual(
            canonical_bytes(restarted_b.serve(request)), canonical_bytes(page)
        )
        self.assertEqual(
            canonical_bytes(self.sync_a.request(request_id=request_id(1), limit=1)),
            canonical_bytes(request),
        )
        with self.assertRaisesRegex(SyncProtocolError, "sync_request_id_conflict"):
            self.sync_a.request(request_id=request_id(1), limit=2)

        fresh_ledger = Ledger(
            self.root_path / "unsolicited" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(SyncProtocolError, "unsolicited_sync_delta"):
            SyncEngine(fresh_ledger).pull(page)
        self.assertEqual(fresh_ledger.events(), [])

        next_request = self.sync_a.request(request_id=request_id(2), limit=1)
        next_page = self.sync_b.serve(next_request)
        self.sync_a.pull(next_page)
        final_request = self.sync_a.request(request_id=request_id(3), limit=8)
        final_page = self.sync_b.serve(final_request)
        self.assertFalse(final_page["more"])
        self.sync_a.pull(final_page)

        reverse = self.sync_b.request(request_id=request_id(4), limit=8)
        self.sync_b.pull(self.sync_a.serve(reverse))
        expected = {
            local_a["event_id"],
            late["event_id"],
            *(item["event_id"] for item in remote),
        }
        self.assertEqual(
            {event["event_id"] for event in self.ledger_a.events()}, expected
        )
        self.assertEqual(
            {event["event_id"] for event in self.ledger_b.events()}, expected
        )
        cursor = self.ledger_a.peer_cursors(peer_id(self.origins["daimonmatrix"]))
        self.assertEqual(cursor[0]["sequence"], 3)

    def test_request_and_page_id_conflicts_are_durable(self) -> None:
        self.append(self.ledger_b, "daimonmatrix", "one")
        request = self.sync_a.request(request_id=request_id(10), limit=1)
        page = self.sync_b.serve(request)

        changed_request = copy.deepcopy(request)
        changed_request["limit"] = 2
        with self.assertRaisesRegex(SyncProtocolError, "origin_equivocation"):
            self.sync_b.serve(changed_request)
        self.assertEqual(self.ledger_b.equivocations()[0]["lane"], "sync_request")

        self.sync_a.pull(page)
        changed_page = copy.deepcopy(page)
        changed_page["more"] = not changed_page["more"]
        core = {key: value for key, value in changed_page.items() if key != "page_hash"}
        changed_page["page_hash"] = hashlib.sha256(
            DELTA_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        with self.assertRaisesRegex(SyncProtocolError, "origin_equivocation"):
            self.sync_a.pull(changed_page)
        self.assertEqual(
            {item["lane"] for item in self.ledger_a.equivocations()}, {"sync_page"}
        )

    def test_transaction_rechecks_cursor_regression_before_any_mutation(self) -> None:
        first = self.append(self.ledger_b, "daimonmatrix", "cursor-one")
        self.append(self.ledger_b, "daimonmatrix", "cursor-two")
        request = self.sync_a.request(request_id=request_id(15), limit=2)
        self.sync_a.pull(self.sync_b.serve(request))
        source = peer_id(self.origins["daimonmatrix"])
        before_events = canonical_bytes(self.ledger_a.events())
        before_cursor = canonical_bytes(self.ledger_a.peer_cursors(source))

        with self.assertRaisesRegex(LedgerError, "peer_cursor_regression"):
            self.ledger_a.ingest_idempotent(
                [first],
                source=source,
                request_id=request_id(16),
                page_hash="f" * 64,
                receipt_base={},
            )

        self.assertEqual(canonical_bytes(self.ledger_a.events()), before_events)
        self.assertEqual(
            canonical_bytes(self.ledger_a.peer_cursors(source)), before_cursor
        )

    def test_corrupt_frozen_outbound_cache_fails_closed(self) -> None:
        self.append(self.ledger_b, "daimonmatrix", "cached-response")
        request = self.sync_a.request(request_id=request_id(17), limit=1)
        self.sync_b.serve(request)
        with closing(sqlite3.connect(self.ledger_b.path)) as database:
            database.execute(
                "UPDATE outbound_sync SET response_json=? WHERE request_id=?",
                (b'{"events":[]}', request["request_id"]),
            )
            database.commit()
        with self.assertRaisesRegex(
            SyncProtocolError, "outbound_sync_response_corrupt"
        ):
            self.sync_b.serve(request)

    def test_tamper_authority_and_conflicting_heads_fail_without_insert(self) -> None:
        first = self.append(self.ledger_b, "daimonmatrix", "one")
        second = self.append(self.ledger_b, "daimonmatrix", "two")
        request = self.sync_a.request(request_id=request_id(20), limit=1)
        page = self.sync_b.serve(request)

        tampered = copy.deepcopy(page)
        tampered["events"][0]["payload"]["summary"] = "tampered"
        with self.assertRaisesRegex(SyncProtocolError, "sync_page_hash_mismatch"):
            self.sync_a.pull(tampered)
        wrong_manifest = copy.deepcopy(page)
        wrong_manifest["manifest_hash"] = "0" * 64
        with self.assertRaisesRegex(SyncProtocolError, "sync_authority_mismatch"):
            self.sync_a.pull(wrong_manifest)
        wrong_request = copy.deepcopy(page)
        wrong_request["request_hash"] = "0" * 64
        core = {
            key: value for key, value in wrong_request.items() if key != "page_hash"
        }
        wrong_request["page_hash"] = hashlib.sha256(
            DELTA_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        with self.assertRaisesRegex(SyncProtocolError, "sync_request_hash_mismatch"):
            self.sync_a.pull(wrong_request)
        with self.assertRaisesRegex(SyncProtocolError, "invalid_sync_limit"):
            self.sync_a.request(request_id=request_id(22), limit=257)
        over_requested_limit = copy.deepcopy(page)
        over_requested_limit["events"].append(second)
        over_requested_limit["more"] = False
        core = {
            key: value
            for key, value in over_requested_limit.items()
            if key != "page_hash"
        }
        over_requested_limit["page_hash"] = hashlib.sha256(
            DELTA_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        with self.assertRaisesRegex(
            SyncProtocolError, "sync_delta_exceeds_requested_limit"
        ):
            self.sync_a.pull(over_requested_limit)
        self.assertEqual(self.ledger_a.events(), [])

        self.sync_a.pull(page)
        regression_request = self.sync_a.request(request_id=request_id(23), limit=1)
        regression_page = self.sync_b.serve(regression_request)
        regression_page["events"] = [first]
        regression_page["more"] = False
        core = {
            key: value for key, value in regression_page.items() if key != "page_hash"
        }
        regression_page["page_hash"] = hashlib.sha256(
            DELTA_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        with self.assertRaisesRegex(SyncProtocolError, "sync_delta_cursor_regression"):
            self.sync_a.pull(regression_page)
        self.assertEqual(len(self.ledger_a.events()), 1)

        conflicting_request = self.sync_a.request(request_id=request_id(21), limit=1)
        conflicting_request["heads"][-1]["tip_hash"] = "0" * 64
        with self.assertRaisesRegex(SyncProtocolError, "origin_equivocation"):
            self.sync_b.serve(conflicting_request)

    def test_sync_and_projection_documents_match_closed_schemas(self) -> None:
        self.append(self.ledger_b, "daimonmatrix", "schema")
        heads = self.sync_a.heads()
        request = self.sync_a.request(request_id=request_id(30), limit=1)
        page = self.sync_b.serve(request)
        receipt = self.sync_a.pull(page)
        projection = ProjectionEngine(self.ledger_a).snapshot()
        self.assertEqual(
            validate_heads_document(
                heads, self.authority, expected_sender=self.origins["legion"]
            ),
            heads,
        )
        self.assertEqual(
            validate_receipt(
                receipt,
                self.authority,
                expected_sender=self.origins["daimonmatrix"],
                expected_receiver=self.origins["legion"],
            ),
            receipt,
        )
        with self.assertRaisesRegex(SyncProtocolError, "sync_wrong_sender"):
            validate_receipt(
                receipt,
                self.authority,
                expected_sender=self.origins["legion"],
            )
        names_and_values = (
            ("heads.schema.json", heads),
            ("sync-request.schema.json", request),
            ("delta.schema.json", page),
            ("sync-receipt.schema.json", receipt),
            ("projection.schema.json", projection),
        )
        schema_root = ROOT / "schemas" / "weave" / "v1"
        schemas = {
            name: json.loads((schema_root / name).read_bytes())
            for name in (
                "event.schema.json",
                "heads.schema.json",
                "sync-request.schema.json",
                "delta.schema.json",
                "sync-receipt.schema.json",
                "projection.schema.json",
            )
        }
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema))
            for schema in schemas.values()
        )
        for name, value in names_and_values:
            schema = schemas[name]
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(
                schema, registry=registry, format_checker=FormatChecker()
            ).validate(value)


class ProjectionTests(RootLedgerFixture):
    def test_local_decision_chain_remote_decision_receipt_and_rebuild(self) -> None:
        target = self.append(self.ledger_b, "daimonmatrix", "shared-observation")
        self.ledger_a.ingest([target], source="test-peer")
        remote_decision = self.ledger_b.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "reject",
                "reason": "remote choice",
            },
            signer=self.signers["daimonmatrix"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        self.ledger_a.ingest([remote_decision], source="test-peer")
        adopt = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "local choice",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 2,
        )
        receipt = self.ledger_a.append_local(
            kind="projection.receipted",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision_event_id": adopt["event_id"],
                "adapter": "synthetic-memory/v1",
                "preview_hash": "a" * 64,
                "intent_hash": "b" * 64,
                "actor": "compaii@legion",
                "authority": "daimon",
                "resource_fence": None,
                "result": "applied",
                "observed_postcondition": {"marker": target["event_id"]},
                "started_at_ms": NOW + 3,
                "completed_at_ms": NOW + 4,
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"], adopt["event_id"]],
            occurred_at_ms=NOW + 4,
        )
        event_schema = json.loads(
            (ROOT / "schemas" / "weave" / "v1" / "event.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(event_schema)
        Draft202012Validator(event_schema, format_checker=FormatChecker()).validate(
            receipt
        )
        revert = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "revert",
                "reason": "local reversal",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            supersedes=adopt["event_id"],
            occurred_at_ms=NOW + 5,
        )

        engine = ProjectionEngine(self.ledger_a)
        snapshot = engine.rebuild()
        entry = next(
            item
            for item in snapshot["entries"]
            if item["event_id"] == target["event_id"]
        )
        self.assertEqual(entry["state"], "reverted")
        self.assertEqual(entry["decision_event_id"], revert["event_id"])
        self.assertEqual(
            entry["local_decision_chain"], [adopt["event_id"], revert["event_id"]]
        )
        self.assertEqual(
            entry["remote_decision_event_ids"], [remote_decision["event_id"]]
        )
        self.assertEqual(entry["projection_receipt_ids"], [receipt["event_id"]])
        self.assertEqual(engine.cached(), snapshot)

        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            engine.rebuild(
                before_replace=lambda _: (_ for _ in ()).throw(
                    RuntimeError("interrupted")
                )
            )
        self.assertEqual(engine.cached(), snapshot)

    def test_cross_target_and_successor_forks_fail_without_implicit_winner(
        self,
    ) -> None:
        first_target = self.append(self.ledger_a, "legion", "first-target")
        second_target = self.append(self.ledger_a, "legion", "second-target")
        root = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=first_target["subject"],
            payload={
                "target_event_id": first_target["event_id"],
                "decision": "adopt",
                "reason": "root",
            },
            signer=self.signers["legion"],
            causal_parents=[first_target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        cross_target = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=second_target["subject"],
            payload={
                "target_event_id": second_target["event_id"],
                "decision": "reject",
                "reason": "invalid cross-target successor",
            },
            signer=self.signers["legion"],
            causal_parents=[second_target["event_id"], root["event_id"]],
            supersedes=root["event_id"],
            occurred_at_ms=NOW + 2,
        )
        first_successor = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=first_target["subject"],
            payload={
                "target_event_id": first_target["event_id"],
                "decision": "reject",
                "reason": "branch one",
            },
            signer=self.signers["legion"],
            causal_parents=[first_target["event_id"], root["event_id"]],
            supersedes=root["event_id"],
            occurred_at_ms=NOW + 3,
        )
        second_successor = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=first_target["subject"],
            payload={
                "target_event_id": first_target["event_id"],
                "decision": "defer",
                "reason": "branch two",
            },
            signer=self.signers["legion"],
            causal_parents=[first_target["event_id"], root["event_id"]],
            supersedes=root["event_id"],
            occurred_at_ms=NOW + 4,
        )
        entries = {
            entry["event_id"]: entry
            for entry in ProjectionEngine(self.ledger_a).snapshot()["entries"]
        }
        self.assertEqual(entries[first_target["event_id"]]["state"], "failed")
        self.assertEqual(entries[second_target["event_id"]]["state"], "failed")
        self.assertEqual(
            entries[first_target["event_id"]]["local_decision_chain"],
            sorted(
                [
                    root["event_id"],
                    first_successor["event_id"],
                    second_successor["event_id"],
                ]
            ),
        )
        self.assertEqual(
            entries[second_target["event_id"]]["local_decision_chain"],
            [cross_target["event_id"]],
        )

    def test_reversal_continues_across_pre_authorized_incarnation_restart(
        self,
    ) -> None:
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
        manifest_value = copy.deepcopy(self.manifest.value)
        old_member = next(
            row
            for row in manifest_value["embodiments"]
            if row["embodiment_id"] == "embodiment:legion"
        )
        manifest_value["embodiments"].append(
            {
                **old_member,
                "incarnation_authorization_id": later["artifact_id"],
                "incarnation_id": "incarnation:legion:1",
            }
        )
        manifest_value["embodiments"].sort(
            key=lambda row: (row["embodiment_id"], row["incarnation_id"])
        )
        manifest = BeingManifest.from_value(manifest_value)
        authority = RootAuthority(
            manifest,
            self.state,
            self.credentials,
            {**self.incarnations, later["artifact_id"]: later},
        )
        path = self.root_path / "incarnation-restart" / "ledger.sqlite"
        old_ledger = Ledger(
            path,
            authority=authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        target = old_ledger.append_local(
            kind="experience.observed",
            subject="restart-target",
            payload={"summary": "restart-target"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        adopt = old_ledger.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "before restart",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        new_origin = {
            **self.origins["legion"],
            "incarnation_id": "incarnation:legion:1",
        }
        new_ledger = Ledger(
            path,
            authority=authority,
            local_origin=new_origin,
            clock=lambda: NOW,
        )
        revert = new_ledger.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "revert",
                "reason": "after restart",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"], adopt["event_id"]],
            supersedes=adopt["event_id"],
            occurred_at_ms=NOW + 2,
        )
        entry = ProjectionEngine(new_ledger).snapshot()["entries"][0]
        self.assertEqual(entry["state"], "reverted")
        self.assertEqual(
            entry["local_decision_chain"], [adopt["event_id"], revert["event_id"]]
        )

    def test_ambiguous_local_decisions_fail_deterministically(self) -> None:
        target = self.append(self.ledger_a, "legion", "ambiguous")
        first = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "one",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        second = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "reject",
                "reason": "two",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 2,
        )
        entry = ProjectionEngine(self.ledger_a).snapshot()["entries"][0]
        self.assertEqual(entry["state"], "failed")
        self.assertEqual(
            entry["local_decision_chain"],
            sorted([first["event_id"], second["event_id"]]),
        )

    def test_receipt_for_non_adopted_decision_is_failed_provenance(self) -> None:
        target = self.append(self.ledger_a, "legion", "invalid-receipt")
        rejection = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "reject",
                "reason": "nothing to project",
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        receipt = self.ledger_a.append_local(
            kind="projection.receipted",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision_event_id": rejection["event_id"],
                "adapter": "synthetic-memory/v1",
                "preview_hash": "a" * 64,
                "intent_hash": "b" * 64,
                "actor": "compaii@legion",
                "authority": "daimon",
                "resource_fence": None,
                "result": "applied",
                "observed_postcondition": {},
                "started_at_ms": NOW + 2,
                "completed_at_ms": NOW + 3,
            },
            signer=self.signers["legion"],
            causal_parents=[target["event_id"], rejection["event_id"]],
            occurred_at_ms=NOW + 3,
        )
        snapshot = ProjectionEngine(self.ledger_a).snapshot()
        ProjectionEngine.verify(snapshot)
        entry = snapshot["entries"][0]
        self.assertEqual(entry["state"], "failed")
        self.assertEqual(entry["invalid_projection_receipt_ids"], [receipt["event_id"]])

    def test_supersession_cycle_stays_incomplete_and_cannot_choose_state(self) -> None:
        target = self.append(self.ledger_a, "legion", "cycle-target")
        first_id = request_id(901)
        second_id = request_id(902)
        first = create_event(
            self.authority,
            self.origins["legion"],
            self.signers["legion"],
            event_id=first_id,
            sequence=2,
            previous_event_id=target["event_id"],
            occurred_at_ms=NOW + 1,
            causal_parents=[target["event_id"]],
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "adopt",
                "reason": "cyclic predecessor",
            },
            supersedes=second_id,
        )
        second = create_event(
            self.authority,
            self.origins["legion"],
            self.signers["legion"],
            event_id=second_id,
            sequence=3,
            previous_event_id=first_id,
            occurred_at_ms=NOW + 2,
            causal_parents=[target["event_id"]],
            kind="adoption.decided",
            subject=target["subject"],
            payload={
                "target_event_id": target["event_id"],
                "decision": "revert",
                "reason": "cyclic successor",
            },
            supersedes=first_id,
        )
        result = self.ledger_a.ingest([first, second], source="cycle-fixture")
        self.assertEqual(result["incomplete"], 2)
        entry = ProjectionEngine(self.ledger_a).snapshot()["entries"][0]
        self.assertEqual(entry["state"], "pending")
        self.assertEqual(entry["local_decision_chain"], [])

    def test_projection_digest_is_independent_of_valid_cross_origin_batching(
        self,
    ) -> None:
        local = self.append(self.ledger_a, "legion", "local")
        remote = self.append(self.ledger_b, "daimonmatrix", "remote")
        self.ledger_a.ingest([remote], source="fixture")
        decision = self.ledger_a.append_local(
            kind="adoption.decided",
            subject=remote["subject"],
            payload={
                "target_event_id": remote["event_id"],
                "decision": "adopt",
                "reason": "deterministic",
            },
            signer=self.signers["legion"],
            causal_parents=[remote["event_id"]],
            occurred_at_ms=NOW + 1,
        )
        first = Ledger(
            self.root_path / "projection-order-one" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        second = Ledger(
            self.root_path / "projection-order-two" / "ledger.sqlite",
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        first.ingest([local, decision], source="legion-batch")
        self.assertEqual(first.incomplete_count(), 1)
        first.ingest([remote], source="remote-batch")
        second.ingest([remote], source="remote-first")
        second.ingest([local, decision], source="legion-second")

        snapshot_one = ProjectionEngine(first).rebuild()
        snapshot_two = ProjectionEngine(second).rebuild()
        self.assertEqual(first.incomplete_count(), 0)
        self.assertEqual(canonical_bytes(snapshot_one), canonical_bytes(snapshot_two))

    def test_cache_hash_validation_and_dm022_schema_migration(self) -> None:
        event = self.append(self.ledger_a, "legion", "migration")
        before = canonical_bytes(event)
        self.ledger_a.initialize()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
            database.execute("DROP TABLE outbound_sync")
            database.execute("DROP TABLE issued_sync")
            database.execute("DROP TABLE inbound_sync")
            database.execute("DROP TABLE projection_cache")
            database.commit()

        reopened = Ledger(
            self.ledger_a.path,
            authority=self.authority,
            local_origin=self.origins["legion"],
            clock=lambda: NOW,
        )
        reopened.initialize()
        with closing(sqlite3.connect(reopened.path)) as database:
            version = database.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            names = {
                row[0]
                for row in database.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        self.assertEqual(version, str(SCHEMA_VERSION))
        self.assertTrue(
            {"outbound_sync", "issued_sync", "inbound_sync", "projection_cache"}
            <= names
        )
        self.assertEqual(canonical_bytes(reopened.events()[0]), before)

        engine = ProjectionEngine(reopened)
        snapshot = engine.rebuild()
        corrupted = copy.deepcopy(snapshot)
        corrupted["entries"][0]["subject"] = "corrupted-but-well-shaped"
        reopened.replace_projection_cache(corrupted)
        with self.assertRaisesRegex(ProjectionError, "projection_hash_mismatch"):
            engine.cached()

        malformed = copy.deepcopy(snapshot)
        malformed["entries"] = [None]
        core = {
            key: value for key, value in malformed.items() if key != "projection_hash"
        }
        malformed["projection_hash"] = hashlib.sha256(
            PROJECTION_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        reopened.replace_projection_cache(malformed)
        with self.assertRaisesRegex(ProjectionError, "invalid_projection_snapshot"):
            engine.cached()

        wrong_authority = copy.deepcopy(snapshot)
        wrong_authority["local_embodiment_id"] = "embodiment:not-this-ledger"
        core = {
            key: value
            for key, value in wrong_authority.items()
            if key != "projection_hash"
        }
        wrong_authority["projection_hash"] = hashlib.sha256(
            PROJECTION_DOMAIN + canonical_bytes(core)
        ).hexdigest()
        reopened.replace_projection_cache(wrong_authority)
        with self.assertRaisesRegex(ProjectionError, "projection_authority_mismatch"):
            engine.cached()


if __name__ == "__main__":
    unittest.main()
