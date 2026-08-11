from __future__ import annotations

import copy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.authority_epochs import (
    AuthorityEpochError,
    RootHistoryAuthority,
    create_embodiment_enrollment,
    verify_embodiment_enrollment,
)
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.identity import signing_descriptor, verify_genesis
from daimon_matrix.ledger import Ledger
from daimon_matrix.operator_rebirth import (
    RebirthError,
    apply_activation_to_runtime_bundle,
    authorize_enrollment_request,
    create_enrollment_request,
    validate_activation,
    validate_enrollment_request,
)
from daimon_matrix.weave import BeingManifest, EventSigner, RootAuthority
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed
from tools.generate_dm078_vectors import generate as generate_vectors

ROOT = Path(__file__).resolve().parents[1]


class TestAdditionalEmbodiment(RootLedgerFixture):
    def request(self, **changes: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "signing_seed": seed("fresh-signing"),
            "encryption_private": seed("fresh-encryption"),
            "transport_seed": seed("fresh-transport"),
            "body_ref": "cluster:daimonmatrix:dm078-fresh",
            "embodiment_id": "embodiment:dm078:fresh",
            "incarnation_id": "incarnation:dm078:fresh:0",
            "principal_id": "compaii@dm078-fresh",
            "created_at_ms": NOW + 10,
            "expires_at_ms": NOW + 60_010,
            "nonce": seed("fresh-request"),
        }
        values.update(changes)
        return create_enrollment_request(self.authority, **values)

    def activation(self) -> tuple[dict[str, Any], dict[str, Any]]:
        request = self.request()
        activation = authorize_enrollment_request(
            request,
            self.authority,
            root_seeds=self.root_seeds[:2],
            issued_at_ms=NOW + 20,
        )
        return request, activation

    def test_target_and_root_never_share_private_material(self) -> None:
        request = self.request()
        partial = request["body"]["credential"]
        assert [row["role"] for row in partial["signatures"]] == [
            "embodiment-acceptance"
        ]
        assert "private" not in json.dumps(request)
        validated = validate_enrollment_request(
            request, self.authority, observed_at_ms=NOW + 20
        )
        assert validated == request

        activation = authorize_enrollment_request(
            request,
            self.authority,
            root_seeds=self.root_seeds[:2],
            issued_at_ms=NOW + 20,
        )
        assert "private" not in json.dumps(activation)
        roles = [row["role"] for row in activation["body"]["credential"]["signatures"]]
        assert roles.count("root-authorization") == 2
        assert roles.count("embodiment-acceptance") == 1

    def test_root_enrollment_preserves_old_history_and_adds_one_body(self) -> None:
        old_event = self.append(self.ledger_a, "legion", "before-enrollment")
        request, activation = self.activation()
        verified, successor, history = validate_activation(
            activation, self.authority, request=request
        )
        assert verified == activation
        assert successor.manifest.value["revision"] == 2
        old_rows = self.manifest.value["embodiments"]
        new_rows = successor.manifest.value["embodiments"]
        assert all(row in new_rows for row in old_rows)
        assert len(new_rows) == len(old_rows) + 1
        origin = activation["body"]["origin"]
        assert (
            successor.manifest.member(
                origin["embodiment_id"], origin["incarnation_id"]
            )["status"]
            == "active"
        )

        advanced = Ledger(
            self.ledger_a.path,
            authority=history,
            local_origin=self.origins["legion"],
            clock=lambda: NOW + 30,
        )
        advanced.initialize()
        assert advanced.event(old_event["event_id"]) == old_event

        fresh = Ledger(
            self.root_path / "fresh" / "ledger.sqlite",
            authority=history,
            local_origin=origin,
            clock=lambda: NOW + 30,
        )
        fresh.initialize()
        assert fresh.ingest(advanced.delta([]), source="compaii@legion")["missing"] == 1
        assert fresh.event(old_event["event_id"]) == old_event
        signing = seed("fresh-signing")
        new_event = fresh.append_local(
            kind="experience.observed",
            subject="fresh-body-awake",
            payload={"summary": "fresh-body-awake"},
            signer=EventSigner(signing_descriptor(signing)["key_id"], signing),
            occurred_at_ms=NOW + 30,
        )
        assert new_event["origin"] == origin
        assert new_event["manifest_hash"] == successor.manifest.digest

    def test_threshold_stale_tamper_replay_and_unrelated_delta_fail(self) -> None:
        request = self.request()
        with self.assertRaisesRegex(RebirthError, "threshold_shortfall"):
            authorize_enrollment_request(
                request,
                self.authority,
                root_seeds=self.root_seeds[:1],
                issued_at_ms=NOW + 20,
            )
        with self.assertRaisesRegex(RebirthError, "not_timely"):
            validate_enrollment_request(
                request, self.authority, observed_at_ms=NOW + 60_010
            )
        changed = copy.deepcopy(request)
        changed["body"]["body_ref"] = "forged"
        with self.assertRaises(RebirthError):
            validate_enrollment_request(
                changed, self.authority, observed_at_ms=NOW + 20
            )
        transport_tampered = copy.deepcopy(request)
        transport_tampered["transport_signature"]["value"] = "A" * 86
        with self.assertRaisesRegex(RebirthError, "transport_signature"):
            validate_enrollment_request(
                transport_tampered, self.authority, observed_at_ms=NOW + 20
            )

        request, activation = self.activation()
        _, successor, history = validate_activation(
            activation, self.authority, request=request
        )
        with self.assertRaises(RebirthError):
            validate_enrollment_request(request, successor, observed_at_ms=NOW + 20)
        altered = copy.deepcopy(successor.manifest.value)
        old = next(
            row
            for row in altered["embodiments"]
            if row["embodiment_id"] == self.origins["legion"]["embodiment_id"]
        )
        old["status"] = "retired"
        forbidden = RootAuthority(
            BeingManifest.from_value(altered),
            self.state,
            successor.credentials,
            successor.incarnations,
        )
        origin = activation["body"]["origin"]
        forbidden_transition = create_embodiment_enrollment(
            self.authority.manifest,
            forbidden.manifest,
            request_id=activation["body"]["request_id"],
            body_ref=origin["body_ref"],
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            embodiment_credential_id=activation["body"]["credential"]["artifact_id"],
            incarnation_authorization_id=activation["body"]["incarnation"][
                "artifact_id"
            ],
            principal_id=origin["principal_id"],
            root_seeds=self.root_seeds[:2],
            issued_at_ms=NOW + 20,
        )
        with self.assertRaisesRegex(AuthorityEpochError, "manifest_change_forbidden"):
            verify_embodiment_enrollment(
                forbidden_transition, self.authority, forbidden
            )
        assert isinstance(history, RootHistoryAuthority)

    def test_activation_updates_public_peers_forward_only(self) -> None:
        request, activation = self.activation()
        existing_target = {
            "embodiment_id": self.origins["daimonmatrix"]["embodiment_id"],
            "endpoint": "http://127.0.0.1:18686/dm-peer/v1",
            "timeout_ms": 5_000,
        }
        bundle = {
            "manifest": copy.deepcopy(self.manifest.value),
            "authority_history": [],
            "credentials": list(self.credentials.values()),
            "incarnations": list(self.incarnations.values()),
            "peer_transport": {"targets": [existing_target]},
        }
        updated = apply_activation_to_runtime_bundle(
            bundle,
            activation,
            self.authority,
            target_endpoint="http://127.0.0.1:28686/dm-peer/v1",
        )
        self.assertEqual(bundle["manifest"], self.manifest.value)
        self.assertEqual(updated["manifest"]["revision"], 2)
        self.assertEqual(len(updated["authority_history"]), 1)
        self.assertEqual(
            {row["embodiment_id"] for row in updated["peer_transport"]["targets"]},
            {
                self.origins["daimonmatrix"]["embodiment_id"],
                activation["body"]["origin"]["embodiment_id"],
            },
        )
        forged = copy.deepcopy(activation)
        forged["body"]["origin"]["principal_id"] = "forged@principal"
        with self.assertRaisesRegex(RebirthError, "origin_mismatch"):
            validate_activation(forged, self.authority, request=request)

    def test_transition_matches_schema_and_canonical_round_trip(self) -> None:
        _, activation = self.activation()
        transition = activation["body"]["transition"]
        schema = json.loads(
            (ROOT / "schemas/weave/v1/embodiment-enrollment.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(
            transition
        )
        assert json.loads(canonical_bytes(transition)) == transition

    def test_public_vectors_verify_and_regenerate_byte_identically(self) -> None:
        vector_root = ROOT / "vectors" / "weave" / "v1" / "embodiment-enrollment"
        index = json.loads((vector_root / "index.json").read_bytes())
        previous = BeingManifest.from_value(
            json.loads((vector_root / index["previous_manifest"]).read_bytes())
        )
        identity = index["identity"]
        state = verify_genesis(
            json.loads((vector_root / identity["genesis"]).read_bytes())
        )
        existing_credential = json.loads(
            (vector_root / identity["existing_embodiment_credential"]).read_bytes()
        )
        existing_incarnation = json.loads(
            (vector_root / identity["existing_incarnation_authorization"]).read_bytes()
        )
        base = RootAuthority(
            previous,
            state,
            {existing_credential["artifact_id"]: existing_credential},
            {existing_incarnation["artifact_id"]: existing_incarnation},
        )
        request = json.loads((vector_root / index["request"]).read_bytes())
        activation = json.loads((vector_root / index["activation"]).read_bytes())
        validate_enrollment_request(request, base, observed_at_ms=NOW + 20)
        validate_activation(activation, base, request=request)
        invalid_request = json.loads(
            (vector_root / index["negative_request"]).read_bytes()
        )
        with self.assertRaisesRegex(RebirthError, "signature"):
            validate_enrollment_request(invalid_request, base, observed_at_ms=NOW + 20)
        invalid_transition = json.loads(
            (vector_root / index["negative_transition"]).read_bytes()
        )
        successor_manifest = BeingManifest.from_value(
            json.loads((vector_root / index["successor_manifest"]).read_bytes())
        )
        enrolled_credential = json.loads(
            (vector_root / index["credential"]).read_bytes()
        )
        enrolled_incarnation = json.loads(
            (vector_root / index["incarnation"]).read_bytes()
        )
        successor = RootAuthority(
            successor_manifest,
            state,
            {
                **base.credentials,
                enrolled_credential["artifact_id"]: enrolled_credential,
            },
            {
                **base.incarnations,
                enrolled_incarnation["artifact_id"]: enrolled_incarnation,
            },
        )
        with self.assertRaisesRegex(AuthorityEpochError, "hash_mismatch"):
            verify_embodiment_enrollment(invalid_transition, base, successor)
        with TemporaryDirectory(prefix="dm078-vectors-") as directory:
            generated = Path(directory)
            generate_vectors(generated)
            expected = {
                path.relative_to(vector_root): path.read_bytes()
                for path in vector_root.rglob("*")
                if path.is_file()
            }
            actual = {
                path.relative_to(generated): path.read_bytes()
                for path in generated.rglob("*")
                if path.is_file()
            }
            self.assertEqual(actual, expected)
