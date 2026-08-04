from __future__ import annotations

import copy
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.authority_epochs import (
    AuthorityEpochError,
    RootHistoryAuthority,
    create_authority_epoch,
    verify_authority_epoch,
)
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.identity import create_incarnation_authorization, verify_genesis
from daimon_matrix.ledger import Ledger, LedgerStateError
from daimon_matrix.local_api import create_request
from daimon_matrix.projections import ProjectionEngine
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import BeingManifest, RootAuthority, WeaveProtocolError
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm079_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]


class AuthorityEpochFixture(RootLedgerFixture):
    def successor(
        self,
    ) -> tuple[
        dict[str, Any],
        BeingManifest,
        RootAuthority,
        dict[str, Any],
        RootHistoryAuthority,
        dict[str, str],
    ]:
        old_origin = self.origins["legion"]
        credential = next(
            value
            for value in self.credentials.values()
            if value["body"]["embodiment_id"] == old_origin["embodiment_id"]
        )
        authorization = create_incarnation_authorization(
            credential,
            self.signing_seeds["legion"],
            incarnation_id="incarnation:legion:1",
            incarnation_sequence=1,
            started_at_ms=NOW + 10,
        )
        rows = copy.deepcopy(self.manifest.value["embodiments"])
        old_row = next(
            row for row in rows if row["embodiment_id"] == old_origin["embodiment_id"]
        )
        old_row["status"] = "retired"
        rows.append(
            {
                **old_row,
                "incarnation_authorization_id": authorization["artifact_id"],
                "incarnation_id": authorization["body"]["incarnation_id"],
                "status": "active",
            }
        )
        rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
        manifest = BeingManifest.from_value(
            {
                **self.manifest.value,
                "revision": self.manifest.value["revision"] + 1,
                "embodiments": rows,
            }
        )
        authority = RootAuthority(
            manifest,
            self.state,
            self.credentials,
            {**self.incarnations, authorization["artifact_id"]: authorization},
        )
        transition = create_authority_epoch(
            self.manifest,
            manifest,
            embodiment_id=old_origin["embodiment_id"],
            previous_incarnation_id=old_origin["incarnation_id"],
            successor_authorization=authorization,
            signing_seed=self.signing_seeds["legion"],
            issued_at_ms=NOW + 10,
        )
        history = RootHistoryAuthority(authority, [self.authority], [transition])
        origin = {
            **old_origin,
            "incarnation_id": authorization["body"]["incarnation_id"],
        }
        return authorization, manifest, authority, transition, history, origin


class AuthorityEpochTests(AuthorityEpochFixture):
    def test_nonempty_ledger_advances_without_rewriting_old_events(self) -> None:
        old = self.append(self.ledger_a, "legion", "before-restart")
        path = self.ledger_a.path
        with closing(sqlite3.connect(path)) as database:
            database.execute(
                "INSERT INTO peer_cursors(peer_id, incarnation_id, sequence, "
                "tip_event_id, tip_hash) VALUES (?, ?, ?, ?, ?)",
                (
                    "peer:restart-proof",
                    old["origin"]["incarnation_id"],
                    old["sequence"],
                    old["event_id"],
                    old["content_hash"],
                ),
            )
            database.execute(
                "INSERT INTO local_operations(client_id, request_id, request_hash, "
                "event_id) VALUES (?, ?, ?, ?)",
                ("client:restart-proof", "request:local", "1" * 64, old["event_id"]),
            )
            database.execute(
                "INSERT INTO rpc_requests(client_id, request_id, request_hash, "
                "method, state, response_json, created_at_ms, completed_at_ms) "
                "VALUES (?, ?, ?, ?, 'pending', NULL, ?, NULL)",
                (
                    "client:restart-proof",
                    "request:rpc",
                    "2" * 64,
                    "event.append",
                    NOW,
                ),
            )
            database.commit()
            operational_before = {
                table: list(database.execute(f"SELECT * FROM {table}"))
                for table in ("peer_cursors", "local_operations", "rpc_requests")
            }
        before = path.read_bytes()
        _, manifest, _, _, history, origin = self.successor()
        restarted = Ledger(
            path,
            authority=history,
            local_origin=origin,
            clock=lambda: NOW + 20,
        )
        restarted.initialize()
        after_transition = path.read_bytes()
        self.assertNotEqual(before, after_transition)
        self.assertEqual(restarted.event(old["event_id"]), old)
        authored = restarted.append_local(
            kind="experience.observed",
            subject="after-restart",
            payload={"summary": "after-restart"},
            signer=self.signers["legion"],
            occurred_at_ms=NOW + 20,
        )
        self.assertEqual(authored["sequence"], 1)
        self.assertIsNone(authored["previous_event_id"])
        self.assertEqual(authored["manifest_hash"], manifest.digest)
        self.assertEqual(
            {event["manifest_hash"] for event in restarted.events()},
            {self.manifest.digest, manifest.digest},
        )
        with closing(sqlite3.connect(path)) as database:
            operational_after = {
                table: list(database.execute(f"SELECT * FROM {table}"))
                for table in ("peer_cursors", "local_operations", "rpc_requests")
            }
        self.assertEqual(operational_after, operational_before)
        projection = ProjectionEngine(restarted).snapshot()
        self.assertEqual(
            {entry["event_id"] for entry in projection["entries"]},
            {old["event_id"], authored["event_id"]},
        )
        with self.assertRaisesRegex(LedgerStateError, "ledger_metadata_mismatch"):
            self.ledger_a.initialize()

    def test_exact_successor_replay_is_idempotent(self) -> None:
        self.append(self.ledger_a, "legion", "before-restart")
        _, _, _, transition, history, origin = self.successor()
        restarted = Ledger(self.ledger_a.path, authority=history, local_origin=origin)
        restarted.initialize()
        first = self.ledger_a.path.read_bytes()
        restarted.initialize()
        self.assertEqual(self.ledger_a.path.read_bytes(), first)
        self.assertEqual(
            verify_authority_epoch(transition, self.authority, history.active),
            transition,
        )

    def test_tamper_fork_and_forbidden_manifest_delta_fail(self) -> None:
        _, _, authority, transition, _, _ = self.successor()
        cases = []
        changed = copy.deepcopy(transition)
        changed["signature"]["value"] = "A" * 86
        cases.append(changed)
        changed = copy.deepcopy(transition)
        changed["previous_manifest_hash"] = "0" * 64
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(AuthorityEpochError):
                verify_authority_epoch(value, self.authority, authority)

        manifest_value = copy.deepcopy(authority.manifest.value)
        other = next(
            row
            for row in manifest_value["embodiments"]
            if row["embodiment_id"] == self.origins["daimonmatrix"]["embodiment_id"]
        )
        other["status"] = "retired"
        forbidden = RootAuthority(
            BeingManifest.from_value(manifest_value),
            self.state,
            authority.credentials,
            authority.incarnations,
        )
        with self.assertRaises(AuthorityEpochError):
            verify_authority_epoch(transition, self.authority, forbidden)

    def test_sequence_body_active_and_history_forks_fail_closed(self) -> None:
        _, _, authority, transition, _, _ = self.successor()
        old_origin = self.origins["legion"]
        credential = next(
            value
            for value in self.credentials.values()
            if value["body"]["embodiment_id"] == old_origin["embodiment_id"]
        )
        for sequence in (0, 2):
            authorization = create_incarnation_authorization(
                credential,
                self.signing_seeds["legion"],
                incarnation_id=f"incarnation:legion:sequence:{sequence}",
                incarnation_sequence=sequence,
                started_at_ms=NOW + 10,
            )
            manifest_value = copy.deepcopy(authority.manifest.value)
            active = next(
                row
                for row in manifest_value["embodiments"]
                if row["embodiment_id"] == old_origin["embodiment_id"]
                and row["status"] == "active"
            )
            active["incarnation_id"] = authorization["body"]["incarnation_id"]
            active["incarnation_authorization_id"] = authorization["artifact_id"]
            candidate_manifest = BeingManifest.from_value(manifest_value)
            candidate = RootAuthority(
                candidate_manifest,
                self.state,
                self.credentials,
                {**authority.incarnations, authorization["artifact_id"]: authorization},
            )
            candidate_transition = create_authority_epoch(
                self.manifest,
                candidate_manifest,
                embodiment_id=old_origin["embodiment_id"],
                previous_incarnation_id=old_origin["incarnation_id"],
                successor_authorization=authorization,
                signing_seed=self.signing_seeds["legion"],
                issued_at_ms=NOW + 10,
            )
            with (
                self.subTest(sequence=sequence),
                self.assertRaisesRegex(
                    AuthorityEpochError, "authority_epoch_sequence_invalid"
                ),
            ):
                verify_authority_epoch(candidate_transition, self.authority, candidate)

        for mutation in ("body", "ambiguous-active", "revive-old"):
            manifest_value = copy.deepcopy(authority.manifest.value)
            active = next(
                row
                for row in manifest_value["embodiments"]
                if row["embodiment_id"] == old_origin["embodiment_id"]
                and row["status"] == "active"
            )
            if mutation == "body":
                active["body_ref"] = "cluster:forbidden"
            elif mutation == "ambiguous-active":
                old = next(
                    row
                    for row in manifest_value["embodiments"]
                    if row["embodiment_id"] == old_origin["embodiment_id"]
                    and row["status"] == "retired"
                )
                old["status"] = "active"
            else:
                active["status"] = "retired"
                old = next(
                    row
                    for row in manifest_value["embodiments"]
                    if row["embodiment_id"] == old_origin["embodiment_id"]
                    and row["incarnation_id"] == old_origin["incarnation_id"]
                )
                old["status"] = "active"
            with (
                self.subTest(mutation=mutation),
                self.assertRaises((AuthorityEpochError, WeaveProtocolError)),
            ):
                candidate = RootAuthority(
                    BeingManifest.from_value(manifest_value),
                    self.state,
                    authority.credentials,
                    authority.incarnations,
                )
                verify_authority_epoch(transition, self.authority, candidate)

        with self.assertRaisesRegex(
            AuthorityEpochError, "authority_epoch_chain_length_mismatch"
        ):
            RootHistoryAuthority(authority, [self.authority], [])

    def test_corrupt_stored_event_rolls_back_epoch_metadata(self) -> None:
        old = self.append(self.ledger_a, "legion", "before-restart")
        _, _, _, _, history, origin = self.successor()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.execute(
                "UPDATE events SET subject='tampered' WHERE event_id=?",
                (old["event_id"],),
            )
            database.commit()
        restarted = Ledger(self.ledger_a.path, authority=history, local_origin=origin)
        with self.assertRaisesRegex(
            LedgerStateError, "authority_epoch_event_verification_failed"
        ):
            restarted.initialize()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            metadata = dict(database.execute("SELECT key, value FROM metadata"))
        self.assertEqual(metadata["manifest_hash"], self.manifest.digest)

    def test_sqlite_fault_before_commit_retains_old_epoch_then_retry_succeeds(
        self,
    ) -> None:
        old = self.append(self.ledger_a, "legion", "before-restart")
        _, manifest, _, _, history, origin = self.successor()
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            database.row_factory = sqlite3.Row
            database.execute(
                "CREATE TEMP TRIGGER fail_epoch BEFORE UPDATE ON metadata "
                "WHEN NEW.key='manifest_hash' BEGIN SELECT RAISE(ABORT, 'fault'); END"
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "fault"):
                self.ledger_a._commit_authority_epoch(
                    database,
                    {
                        "accepted_manifest_hashes": json.dumps(
                            list(history.accepted_manifest_hashes),
                            separators=(",", ":"),
                        ),
                        "being_ref": manifest.being_ref,
                        "local_embodiment_id": origin["embodiment_id"],
                        "manifest_hash": manifest.digest,
                        "schema_version": "3",
                        "trust_mode": manifest.trust_mode,
                    },
                )
            metadata = dict(database.execute("SELECT key, value FROM metadata"))
        self.assertEqual(metadata["manifest_hash"], self.manifest.digest)
        self.assertEqual(self.ledger_a.event(old["event_id"]), old)
        restarted = Ledger(self.ledger_a.path, authority=history, local_origin=origin)
        restarted.initialize()
        self.assertEqual(restarted.event(old["event_id"]), old)
        with closing(sqlite3.connect(self.ledger_a.path)) as database:
            metadata = dict(database.execute("SELECT key, value FROM metadata"))
        self.assertEqual(metadata["manifest_hash"], manifest.digest)

    def test_public_vectors_verify_and_regenerate_byte_identically(self) -> None:
        vector_root = ROOT / "vectors" / "weave" / "v1" / "authority-epoch"
        index = cast(
            dict[str, Any], json.loads((vector_root / "index.json").read_bytes())
        )

        def load(relative: str) -> dict[str, Any]:
            return cast(
                dict[str, Any], json.loads((vector_root / relative).read_bytes())
            )

        def identity(name: str) -> dict[str, Any]:
            return load(index["identity"][name])

        state = verify_genesis(identity("genesis"))
        credential = identity("embodiment_credential")
        previous_authorization = identity("previous_incarnation_authorization")
        successor_authorization = load(index["successor_authorization"])
        credentials = {credential["artifact_id"]: credential}
        incarnations = {
            previous_authorization["artifact_id"]: previous_authorization,
            successor_authorization["artifact_id"]: successor_authorization,
        }
        previous = RootAuthority(
            BeingManifest.from_value(load(index["previous_manifest"])),
            state,
            credentials,
            incarnations,
        )
        successor = RootAuthority(
            BeingManifest.from_value(load(index["successor_manifest"])),
            state,
            credentials,
            incarnations,
        )
        transition = load(index["valid_successor"])
        self.assertEqual(
            verify_authority_epoch(transition, previous, successor), transition
        )
        with self.assertRaises(AuthorityEpochError):
            verify_authority_epoch(
                load(index["negative_successor"]), previous, successor
            )
        schema = json.loads(
            (ROOT / "schemas/weave/v1/authority-epoch.schema.json").read_bytes()
        )
        Draft202012Validator(schema).validate(transition)
        with TemporaryDirectory(prefix="dm079-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected_files = sorted(
                path.relative_to(vector_root) for path in vector_root.rglob("*.json")
            )
            generated_files = sorted(
                path.relative_to(generated) for path in generated.rglob("*.json")
            )
            self.assertEqual(generated_files, expected_files)
            for relative in expected_files:
                self.assertEqual(
                    (generated / relative).read_bytes(),
                    (vector_root / relative).read_bytes(),
                )


class HostedAuthorityEpochTests(RuntimeFixture):
    def test_v2_bundle_reopens_existing_runtime_under_exact_successor(self) -> None:
        state_root, old_bundle, capability, now_ms = self.make_process_bundle()
        old_runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: now_ms,
        )
        old_event = old_runtime.service.ledger.append_local(
            kind="experience.observed",
            subject="before-hosted-restart",
            payload={"summary": "before-hosted-restart"},
            signer=old_runtime.service.signer,
            occurred_at_ms=now_ms,
        )
        old_origin = self.origins["legion"]
        credential = next(iter(self.credentials.values()))
        new_authorization = create_incarnation_authorization(
            credential,
            self.signing_seeds["legion"],
            incarnation_id="incarnation:hosted:1",
            incarnation_sequence=1,
            started_at_ms=now_ms + 10,
        )
        rows = copy.deepcopy(self.manifest.value["embodiments"])
        rows[0]["status"] = "retired"
        rows.append(
            {
                **rows[0],
                "incarnation_authorization_id": new_authorization["artifact_id"],
                "incarnation_id": new_authorization["body"]["incarnation_id"],
                "status": "active",
            }
        )
        rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
        successor_manifest = BeingManifest.from_value(
            {
                **self.manifest.value,
                "revision": 2,
                "embodiments": rows,
            }
        )
        transition = create_authority_epoch(
            self.manifest,
            successor_manifest,
            embodiment_id=old_origin["embodiment_id"],
            previous_incarnation_id=old_origin["incarnation_id"],
            successor_authorization=new_authorization,
            signing_seed=self.signing_seeds["legion"],
            issued_at_ms=now_ms + 10,
        )
        new_origin = {
            **old_origin,
            "incarnation_id": new_authorization["body"]["incarnation_id"],
        }
        new_bundle = {
            **old_bundle,
            "schema": "dm.runtime.bundle/v2",
            "authority_history": [
                {
                    "manifest": self.manifest.value,
                    "successor": transition,
                }
            ],
            "manifest": successor_manifest.value,
            "incarnations": [*old_bundle["incarnations"], new_authorization],
            "local_origin": new_origin,
        }
        root = Path(__file__).resolve().parents[1]
        for schema_path, value in (
            (root / "schemas/hosted/v2/bundle.schema.json", new_bundle),
            (root / "schemas/weave/v1/authority-epoch.schema.json", transition),
        ):
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(new_bundle))
        bundle_path.chmod(0o600)
        restarted = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: now_ms + 20,
        )
        self.assertEqual(
            restarted.service.ledger.event(old_event["event_id"]), old_event
        )
        request = create_request(
            capability,
            request_id="30000000-0000-4000-8000-000000000079",
            issued_at_ms=now_ms + 20,
            method="scope.me",
            params={},
            nonce=b"e" * 16,
        )
        response = restarted.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["origin"], new_origin)
        self.assertEqual(
            response["result"]["incarnation_authorization_ref"],
            new_authorization["artifact_id"],
        )
        status_request = create_request(
            capability,
            request_id="30000000-0000-4000-8000-000000000080",
            issued_at_ms=now_ms + 20,
            method="runtime.status",
            params={},
            nonce=b"f" * 16,
        )
        status = restarted.service.handle(status_request)["result"]
        self.assertEqual(
            status["authority_epoch"],
            {
                "schema": "dm.we.authority-epoch-status/v1",
                "active_manifest_hash": successor_manifest.digest,
                "accepted_manifest_hashes": sorted(
                    [self.manifest.digest, successor_manifest.digest]
                ),
                "epoch_count": 2,
            },
        )

        bundle_path.write_bytes(canonical_bytes(old_bundle))
        bundle_path.chmod(0o600)
        with self.assertRaisesRegex(LedgerStateError, "ledger_metadata_mismatch"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: now_ms + 20,
            )
