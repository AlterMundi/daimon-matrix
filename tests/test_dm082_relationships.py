from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.conformance import _test_exists
from daimon_matrix.ledger import Ledger
from daimon_matrix.local_api import create_capability, create_request
from daimon_matrix.relationship_store import (
    RelationshipServiceContext,
    RelationshipStore,
    RelationshipStoreError,
    RelationshipView,
)
from daimon_matrix.relationships import (
    CARD_SCHEMA,
    GRANT_REVOCATION_SCHEMA,
    INVITATION_SCHEMA,
    MAX_CAPABILITIES,
    MAX_CARD_LIFETIME_MS,
    MAX_DELEGATION_DEPTH,
    MAX_GRANT_LIFETIME_MS,
    MAX_GRANTS,
    MAX_INVITATION_LIFETIME_MS,
    MAX_MEMBERS,
    MAX_OFFER_LIFETIME_MS,
    MAX_PERMISSIONS,
    MAX_PROPOSED_GRANTS,
    MAX_RESOURCES,
    MAX_ROLES,
    MAX_ROUTES,
    MEMBERSHIP_ACCEPTANCE_SCHEMA,
    MEMBERSHIP_EXPULSION_SCHEMA,
    MEMBERSHIP_LEAVE_SCHEMA,
    RelationshipError,
    VerifiedTribeSnapshot,
    card_series_id,
    grant_id,
    invitation_id,
    relationship_event_subject,
    resource_ref,
    validate_relationship_event_payload,
)
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import RELATIONSHIP_METHODS, HostedWeave
from daimon_matrix.synthetic_relationships import NOW, _identity, _Journey, _seed, _uuid
from daimon_matrix.weave import WeaveProtocolError, create_event
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm082_vectors import generate as generate_dm082_vectors

ROOT = Path(__file__).resolve().parents[1]


def _event(
    journey: _Journey,
    *,
    kind: str | None = None,
    event_id: str | None = None,
    subject: str | None = None,
    being_ref: str | None = None,
) -> dict[str, Any]:
    matches = [
        event
        for event in journey.store.events()
        if (kind is None or event["kind"] == kind)
        and (event_id is None or event["event_id"] == event_id)
        and (subject is None or event["subject"] == subject)
        and (being_ref is None or event["being_ref"] == being_ref)
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected one event, found {len(matches)}")
    return matches[0]


def _card_payload(journey: _Journey, label: str) -> dict[str, Any]:
    identity = journey.identities[label]
    return {
        "schema": CARD_SCHEMA,
        "card_series_id": card_series_id(identity.state.being_ref),
        "sequence": 0,
        "previous_card_event_id": None,
        "being_ref": identity.state.being_ref,
        "control_position": {
            "manifest_hash": identity.authority.manifest.digest,
            "embodiment_id": identity.origin["embodiment_id"],
            "incarnation_id": identity.origin["incarnation_id"],
        },
        "encryption_key": identity.credential["body"]["encryption_key"],
        "route_refs": [f"dm:route:v1:{label}"],
        "capability_refs": ["dm:capability:v1:relationship-v1"],
        "resources": [],
        "issued_at_ms": NOW,
        "expires_at_ms": NOW + 60_000,
    }


def _ref(event: dict[str, Any]) -> dict[str, str]:
    return {"event_hash": event["content_hash"], "event_id": event["event_id"]}


class RelationshipContractTests(unittest.TestCase):
    def test_generated_positive_negative_vectors_and_scenario_map_are_exact(
        self,
    ) -> None:
        outputs = generate_dm082_vectors()
        self.assertTrue(outputs)
        for path, expected in outputs.items():
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.read_bytes(), expected, path)

        index = json.loads((ROOT / "vectors/relationships/v1/index.json").read_bytes())
        self.assertEqual(index["schema"], "dm.relationship-vector-index/v1")
        for entry in index["entries"]:
            raw = (ROOT / "vectors/relationships/v1" / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            if entry["expected"] == "accept":
                event = json.loads(raw)
                validate_relationship_event_payload(
                    event["kind"],
                    event["payload"],
                    author_being_ref=event["being_ref"],
                    causal_parents=event["causal_parents"],
                )
            else:
                vector = json.loads(raw)
                event = vector["document"]
                with self.assertRaisesRegex(
                    RelationshipError, vector["expected_error"]
                ):
                    validate_relationship_event_payload(
                        event["kind"],
                        event["payload"],
                        author_being_ref=event["being_ref"],
                        causal_parents=event["causal_parents"],
                    )

        scenarios = json.loads(
            (ROOT / "conformance/relationship-v1-scenarios.json").read_bytes()
        )
        self.assertEqual(scenarios["schema"], "dm.relationship-scenario-registry/v1")
        self.assertGreaterEqual(len(scenarios["rows"]), 10)
        for row in scenarios["rows"]:
            self.assertTrue(row["evidence"])
            for test_id in row["evidence"]:
                _test_exists(test_id, ROOT)

    def test_published_schemas_and_fixture_cover_every_signed_payload(self) -> None:
        contracts = json.loads(
            (ROOT / "schemas/relationships/v1/contracts.schema.json").read_bytes()
        )
        synthetic = json.loads(
            (ROOT / "schemas/relationships/v1/synthetic.schema.json").read_bytes()
        )
        for schema in (contracts, synthetic):
            Draft202012Validator.check_schema(schema)
        contract_validator = Draft202012Validator(
            contracts, format_checker=FormatChecker()
        )
        report_validator = Draft202012Validator(
            synthetic, format_checker=FormatChecker()
        )
        with tempfile.TemporaryDirectory(prefix="dm082-schema-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            for event in journey.store.events():
                contract_validator.validate(event["payload"])
            fixture = (
                ROOT / "conformance/fixtures/dm082-synthetic-relationships.json"
            ).read_bytes()
            self.assertEqual(fixture, canonical_bytes(report) + b"\n")
            report_validator.validate(report)
            changed = copy.deepcopy(report)
            changed["unexpected"] = True
            with self.assertRaises(ValidationError):
                report_validator.validate(changed)

    def test_local_api_schema_covers_every_relationship_method_exactly(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/hosted/v1/local-api.schema.json").read_bytes()
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        capability = create_capability(
            _seed("relationship-local-api"),
            client_id="client:dm082-schema",
            methods=sorted(RELATIONSHIP_METHODS),
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 1,
        )
        read_params: dict[str, dict[str, Any]] = {
            "relationship.cursor": {},
            "relationship.disclose": {
                "at_ms": None,
                "classification": "shareable",
                "operation": "read",
                "requester_being_ref": "dm:being:v1:requester",
                "resource_ref": "dm:relationship-resource:v1:resource",
            },
            "relationship.event.ingest": {"event": {}},
            "relationship.snapshot": {
                "at_ms": None,
                "tribe_ref": "dm:tribe:v1:synthetic",
            },
            "relationship.status": {"at_ms": None},
        }
        for index, method in enumerate(sorted(RELATIONSHIP_METHODS)):
            request = create_request(
                capability,
                request_id=_uuid(f"local-api:{index}"),
                issued_at_ms=NOW,
                method=method,
                params=read_params.get(method, {"payload": {}}),
                nonce=_seed(f"local-api-nonce:{index}")[:16],
            )
            validator.validate(request)
            changed = copy.deepcopy(request)
            changed["params"]["unexpected"] = True
            with self.assertRaises(ValidationError):
                validator.validate(changed)

    def test_synthetic_journey_is_deterministic_and_cascades_revocation(self) -> None:
        reports = []
        for label in ("a", "b"):
            with tempfile.TemporaryDirectory(prefix=f"dm082-{label}-") as temporary:
                journey = _Journey(Path(temporary))
                reports.append(journey.run())
        self.assertEqual(reports[0], reports[1])
        report = reports[0]
        self.assertEqual(len(report["being_refs"]), 3)
        self.assertEqual(report["final_history"]["complete_event_count"], 17)
        self.assertEqual(
            report["final_history"]["grants"][report["grant_id"]], "revoked"
        )
        self.assertEqual(
            report["final_history"]["grants"][report["child_grant_id"]],
            "revoked",
        )
        self.assertIsInstance(report["evidence"]["message_event_id"], str)
        self.assertTrue(
            report["invariants"]["recipient_encrypted_delivery_opens_only_after_grant"]
        )
        self.assertTrue(
            report["invariants"]["revocation_blocks_disclosure_before_sealing"]
        )
        self.assertTrue(all(report["invariants"].values()))

    def test_known_root_inventory_verifies_foreign_receipt_without_opening_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-root-inventory-") as temporary:
            journey = _Journey(Path(temporary))
            outsider = _identity("outsider")
            event = create_event(
                outsider.authority,
                outsider.origin,
                outsider.signer,
                event_id=_uuid("unknown-root-event"),
                sequence=1,
                previous_event_id=None,
                occurred_at_ms=NOW,
                causal_parents=(),
                kind="experience.observed",
                subject="unknown-root",
                payload={"value": "not-in-the-explicit-inventory"},
                sensitivity="shareable",
            )
            with self.assertRaisesRegex(WeaveProtocolError, "unknown_root_authority"):
                journey.ledger.ingest([event], source="synthetic:outsider")

    def test_closed_payload_author_derived_id_and_signed_time_are_enforced(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-contract-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            member = journey.identities["member"]
            card = _event(
                journey,
                kind="matrix/relationship-card",
                being_ref=founder.state.being_ref,
            )
            payload = copy.deepcopy(card["payload"])
            with self.assertRaisesRegex(
                RelationshipError, "relationship_event_author_mismatch"
            ):
                validate_relationship_event_payload(
                    "matrix/relationship-card",
                    payload,
                    author_being_ref=member.state.being_ref,
                    causal_parents=(),
                )
            payload["unexpected"] = True
            with self.assertRaisesRegex(RelationshipError, "invalid_relationship_card"):
                validate_relationship_event_payload(
                    "matrix/relationship-card",
                    payload,
                    author_being_ref=founder.state.being_ref,
                    causal_parents=(),
                )

            grant = _event(journey, event_id=report["evidence"]["grant_event_id"])
            self_grant = copy.deepcopy(grant["payload"])
            self_grant["subject_being_ref"] = founder.state.being_ref
            with self.assertRaisesRegex(
                RelationshipError, "invalid_relationship_grant"
            ):
                validate_relationship_event_payload(
                    "matrix/relationship-grant",
                    self_grant,
                    author_being_ref=founder.state.being_ref,
                    causal_parents=(),
                )

            normalized = validate_relationship_event_payload(
                "matrix/relationship-card",
                card["payload"],
                author_being_ref=founder.state.being_ref,
                causal_parents=(),
            )
            with self.assertRaisesRegex(
                WeaveProtocolError, "relationship_event_time_mismatch"
            ):
                create_event(
                    founder.authority,
                    founder.origin,
                    founder.signer,
                    event_id="82000000-0000-4000-8000-000000000099",
                    sequence=1,
                    previous_event_id=None,
                    occurred_at_ms=NOW + 1,
                    causal_parents=(),
                    kind="matrix/relationship-card",
                    subject=relationship_event_subject(
                        "matrix/relationship-card", normalized
                    ),
                    payload=normalized,
                    supersedes=None,
                    sensitivity="shareable",
                )

    def test_evidence_is_effective_only_after_its_signed_time(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-time-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            offered = journey.store.view(
                at_ms=NOW + 1, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                offered.relationships[report["relationship_id"]]["state"], "offered"
            )
            self.assertNotIn(report["grant_id"], offered.grants)

            active = journey.store.view(
                at_ms=NOW + 8, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                active.relationships[report["relationship_id"]]["state"], "active"
            )
            self.assertEqual(active.grants[report["grant_id"]]["state"], "active")
            self.assertEqual(active.tribes[report["tribe_ref"]]["founder_epoch"], 0)
            self.assertNotIn(report["child_grant_id"], active.grants)

            transfer_pending = journey.store.view(
                at_ms=NOW + 14, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                transfer_pending.tribes[report["tribe_ref"]]["founder_epoch"], 0
            )
            transferred = journey.store.view(
                at_ms=NOW + 15, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                transferred.tribes[report["tribe_ref"]]["founder_epoch"], 1
            )
            self.assertEqual(transferred.grants[report["grant_id"]]["state"], "active")

    def test_founder_transfer_requires_order_and_active_successor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-founder-time-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            events = journey.store.events()
            transfer = _event(journey, event_id=report["evidence"]["transfer_event_id"])
            original_acceptance = _event(
                journey,
                event_id=report["evidence"]["transfer_acceptance_event_id"],
            )
            member = journey.identities["member"]
            early_acceptance = journey.append(
                "member",
                "matrix/tribe-founder-acceptance",
                {
                    **original_acceptance["payload"],
                    "accepted_at_ms": transfer["payload"]["issued_at_ms"] - 1,
                },
                at_ms=transfer["payload"]["issued_at_ms"] - 1,
            )
            early_only = RelationshipView(
                [
                    event
                    for event in journey.store.events()
                    if event["event_id"]
                    not in {
                        original_acceptance["event_id"],
                        report["evidence"]["revocation_event_id"],
                    }
                ],
                at_ms=NOW + 17,
                card_verifier=journey.card_verifier,
            )
            self.assertEqual(early_only.tribes[report["tribe_ref"]]["founder_epoch"], 0)
            self.assertIn(
                early_acceptance["event_id"],
                {event["event_id"] for event in journey.store.events()},
            )

            without_membership = RelationshipView(
                [
                    event
                    for event in events
                    if event["event_id"] != report["evidence"]["membership_event_id"]
                ],
                at_ms=NOW + 17,
                card_verifier=journey.card_verifier,
            )
            self.assertEqual(
                without_membership.tribes[report["tribe_ref"]]["state"], "forked"
            )
            self.assertEqual(
                without_membership.tribes[report["tribe_ref"]]["founder_being_ref"],
                member.state.being_ref,
            )

    def test_every_owned_v1_bound_accepts_exact_and_rejects_plus_one(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-bounds-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            card = _event(
                journey,
                kind="matrix/relationship-card",
                being_ref=founder.state.being_ref,
            )["payload"]
            offer = _event(journey, event_id=report["evidence"]["offer_event_id"])[
                "payload"
            ]
            invitation = _event(
                journey,
                kind="matrix/tribe-invitation",
                being_ref=founder.state.being_ref,
            )["payload"]
            grant = _event(journey, event_id=report["evidence"]["grant_event_id"])[
                "payload"
            ]

            def accept(kind: str, payload: dict[str, Any]) -> None:
                validate_relationship_event_payload(
                    kind,
                    payload,
                    author_being_ref=founder.state.being_ref,
                    causal_parents=(),
                )

            def reject(kind: str, payload: dict[str, Any], code: str) -> None:
                with self.assertRaisesRegex(RelationshipError, code):
                    accept(kind, payload)

            for field, maximum, prefix in (
                ("route_refs", MAX_ROUTES, "route"),
                ("capability_refs", MAX_CAPABILITIES, "capability"),
            ):
                exact = copy.deepcopy(card)
                exact[field] = [
                    f"dm:{prefix}:v1:{index:03d}" for index in range(maximum)
                ]
                accept("matrix/relationship-card", exact)
                exact[field].append(f"dm:{prefix}:v1:{maximum:03d}")
                reject("matrix/relationship-card", exact, "invalid_relationship_card")

            resources: list[dict[str, Any]] = []
            for index in range(MAX_RESOURCES + 1):
                descriptor = {
                    "schema": "dm.relationship.resource/v1",
                    "resource_nonce": b64url(_seed(f"bound-resource:{index}")),
                    "controller_being_ref": founder.state.being_ref,
                    "kind": "knowledge",
                    "classification": "shareable",
                    "operations": ["read"],
                    "descriptor_ref": f"dm:content:v1:bound-{index:03d}",
                }
                resources.append(
                    {"resource_ref": resource_ref(descriptor), "descriptor": descriptor}
                )
            resources.sort(key=lambda item: item["resource_ref"])
            exact_card = copy.deepcopy(card)
            exact_card["resources"] = resources[:MAX_RESOURCES]
            accept("matrix/relationship-card", exact_card)
            exact_card["resources"] = resources
            reject("matrix/relationship-card", exact_card, "invalid_relationship_card")

            exact_card = copy.deepcopy(card)
            exact_card["expires_at_ms"] = (
                exact_card["issued_at_ms"] + MAX_CARD_LIFETIME_MS
            )
            accept("matrix/relationship-card", exact_card)
            exact_card["expires_at_ms"] += 1
            reject("matrix/relationship-card", exact_card, "invalid_relationship_card")
            exact_card = copy.deepcopy(card)
            exact_card["sequence"] = 2**53 - 1
            exact_card["previous_card_event_id"] = (
                "82000000-0000-4000-8000-000000000098"
            )
            accept("matrix/relationship-card", exact_card)
            exact_card["sequence"] += 1
            reject("matrix/relationship-card", exact_card, "invalid_relationship_card")

            exact_offer = copy.deepcopy(offer)
            exact_offer["expires_at_ms"] = (
                exact_offer["issued_at_ms"] + MAX_OFFER_LIFETIME_MS
            )
            accept("matrix/relationship-offer", exact_offer)
            exact_offer["expires_at_ms"] += 1
            reject(
                "matrix/relationship-offer", exact_offer, "invalid_relationship_offer"
            )
            exact_offer = copy.deepcopy(offer)
            exact_offer["roles"] = [f"role-{index:03d}" for index in range(MAX_ROLES)]
            accept("matrix/relationship-offer", exact_offer)
            exact_offer["roles"].append(f"role-{MAX_ROLES:03d}")
            reject(
                "matrix/relationship-offer", exact_offer, "invalid_relationship_offer"
            )
            proposals: list[dict[str, Any]] = []
            for index in range(MAX_PROPOSED_GRANTS + 1):
                proposal = copy.deepcopy(offer["proposed_grants"][0])
                proposal["not_before_ms"] = NOW + index
                proposal["expires_at_ms"] = NOW + 100_000 + index
                proposals.append(proposal)
            proposals.sort(key=canonical_bytes)
            exact_offer = copy.deepcopy(offer)
            exact_offer["proposed_grants"] = proposals[:MAX_PROPOSED_GRANTS]
            accept("matrix/relationship-offer", exact_offer)
            exact_offer["proposed_grants"] = proposals
            reject(
                "matrix/relationship-offer", exact_offer, "invalid_relationship_offer"
            )

            exact_invitation = copy.deepcopy(invitation)
            exact_invitation["expires_at_ms"] = (
                exact_invitation["issued_at_ms"] + MAX_INVITATION_LIFETIME_MS
            )
            accept("matrix/tribe-invitation", exact_invitation)
            exact_invitation["expires_at_ms"] += 1
            reject(
                "matrix/tribe-invitation", exact_invitation, "invalid_tribe_invitation"
            )

            exact_grant = copy.deepcopy(grant)
            exact_grant["expires_at_ms"] = (
                exact_grant["not_before_ms"] + MAX_GRANT_LIFETIME_MS
            )
            accept("matrix/relationship-grant", exact_grant)
            exact_grant["expires_at_ms"] += 1
            reject(
                "matrix/relationship-grant", exact_grant, "invalid_relationship_grant"
            )
            exact_grant = copy.deepcopy(grant)
            permission = exact_grant["permissions"][0]
            permission["remaining_delegation_depth"] = MAX_DELEGATION_DEPTH
            accept("matrix/relationship-grant", exact_grant)
            permission["remaining_delegation_depth"] += 1
            reject(
                "matrix/relationship-grant", exact_grant, "invalid_relationship_grant"
            )
            exact_grant = copy.deepcopy(grant)
            exact_grant["permissions"][0]["operations"] = [
                f"op{index:03d}" for index in range(MAX_PERMISSIONS)
            ]
            accept("matrix/relationship-grant", exact_grant)
            exact_grant["permissions"][0]["operations"].append(
                f"op{MAX_PERMISSIONS:03d}"
            )
            reject(
                "matrix/relationship-grant", exact_grant, "invalid_relationship_grant"
            )
            exact_grant = copy.deepcopy(grant)
            permissions: list[dict[str, Any]] = []
            for index in range(MAX_PERMISSIONS + 1):
                item = copy.deepcopy(grant["permissions"][0])
                item["classification"] = f"class{index:03d}"
                permissions.append(item)
            exact_grant["permissions"] = permissions[:MAX_PERMISSIONS]
            accept("matrix/relationship-grant", exact_grant)
            exact_grant["permissions"] = permissions
            reject(
                "matrix/relationship-grant", exact_grant, "invalid_relationship_grant"
            )

            active = journey.store.view(
                at_ms=NOW + 8, card_verifier=journey.card_verifier
            ).snapshot(report["tribe_ref"])
            snapshot = copy.deepcopy(dict(active.value))
            founder_row = cast(
                dict[str, Any],
                next(
                    row
                    for row in snapshot["members"]
                    if row["principal_id"] == snapshot["founder_principal_id"]
                ),
            )
            members: list[dict[str, Any]] = [founder_row]
            for index in range(MAX_MEMBERS - 1):
                members.append(
                    {
                        **founder_row,
                        "embodiment_id": f"embodiment:bound:{index:03d}",
                        "membership_ref": f"membership:bound:{index:03d}",
                        "principal_id": f"member:bound:{index:03d}",
                    }
                )
            snapshot["members"] = sorted(members, key=lambda row: row["principal_id"])
            VerifiedTribeSnapshot.from_value(snapshot, verifier=lambda _: None)
            snapshot["members"].append(
                {
                    **founder_row,
                    "embodiment_id": "embodiment:bound:overflow",
                    "membership_ref": "membership:bound:overflow",
                    "principal_id": "member:bound:overflow",
                }
            )
            snapshot["members"].sort(key=lambda row: row["principal_id"])
            with self.assertRaisesRegex(RelationshipError, "invalid_tribe_members"):
                VerifiedTribeSnapshot.from_value(snapshot, verifier=lambda _: None)

            snapshot = copy.deepcopy(dict(active.value))
            grant_row = cast(dict[str, Any], snapshot["grants"][0])
            snapshot["grants"] = [
                {**grant_row, "grant_ref": f"grant:bound:{index:04d}"}
                for index in range(MAX_GRANTS)
            ]
            VerifiedTribeSnapshot.from_value(snapshot, verifier=lambda _: None)
            snapshot["grants"].append(
                {**grant_row, "grant_ref": f"grant:bound:{MAX_GRANTS:04d}"}
            )
            with self.assertRaisesRegex(RelationshipError, "invalid_tribe_grants"):
                VerifiedTribeSnapshot.from_value(snapshot, verifier=lambda _: None)

    def test_one_sided_consent_and_unaccepted_grant_are_inert(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-consent-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            events = journey.store.events()
            acceptance_id = report["evidence"]["acceptance_event_id"]
            without_consent = RelationshipView(
                [event for event in events if event["event_id"] != acceptance_id],
                at_ms=NOW + 8,
                card_verifier=journey.card_verifier,
            )
            self.assertEqual(
                without_consent.relationships[report["relationship_id"]]["state"],
                "offered",
            )
            self.assertEqual(
                len(without_consent.tribes[report["tribe_ref"]]["memberships"]),
                1,
            )
            self.assertEqual(
                without_consent.grants[report["grant_id"]]["state"], "incomplete"
            )

            grant_acceptance_id = report["evidence"]["grant_acceptance_event_id"]
            without_grant_acceptance = RelationshipView(
                [event for event in events if event["event_id"] != grant_acceptance_id],
                at_ms=NOW + 8,
                card_verifier=journey.card_verifier,
            )
            self.assertEqual(
                without_grant_acceptance.grants[report["grant_id"]]["state"],
                "offered",
            )
            self.assertEqual(
                without_grant_acceptance.snapshot(report["tribe_ref"]).value["grants"],
                [],
            )

    def test_membership_reentry_requires_exact_terminal_predecessor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-reentry-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            member = journey.identities["member"]
            first_membership = _event(
                journey, event_id=report["evidence"]["membership_event_id"]
            )
            leave = journey.append(
                "member",
                "matrix/tribe-membership-leave",
                {
                    "schema": MEMBERSHIP_LEAVE_SCHEMA,
                    "tribe_ref": report["tribe_ref"],
                    "founder_epoch": 0,
                    "member_being_ref": member.state.being_ref,
                    "membership_acceptance_ref": _ref(first_membership),
                    "reason": "synthetic-reentry",
                    "terminated_at_ms": NOW + 8,
                },
                at_ms=NOW + 8,
            )
            nonce = b64url(_seed("membership-reentry"))
            invitation_identifier = invitation_id(
                tribe=report["tribe_ref"],
                founder_epoch=0,
                invitee_being_ref=member.state.being_ref,
                nonce=nonce,
            )
            invitation = journey.append(
                "founder",
                "matrix/tribe-invitation",
                {
                    "schema": INVITATION_SCHEMA,
                    "tribe_ref": report["tribe_ref"],
                    "founder_epoch": 0,
                    "founder_being_ref": founder.state.being_ref,
                    "invitation_id": invitation_identifier,
                    "invitee_being_ref": member.state.being_ref,
                    "nonce": nonce,
                    "issued_at_ms": NOW + 9,
                    "expires_at_ms": NOW + 14,
                },
                at_ms=NOW + 9,
            )
            journey.append(
                "member",
                "matrix/tribe-membership-acceptance",
                {
                    "schema": MEMBERSHIP_ACCEPTANCE_SCHEMA,
                    "tribe_ref": report["tribe_ref"],
                    "founder_epoch": 0,
                    "invitation_ref": _ref(invitation),
                    "invitee_being_ref": member.state.being_ref,
                    "membership_sequence": 1,
                    "previous_membership_terminal_ref": _ref(leave),
                    "accepted_at_ms": NOW + 10,
                },
                at_ms=NOW + 10,
            )
            view = journey.store.view(
                at_ms=NOW + 14, card_verifier=journey.card_verifier
            )
            membership = view.tribes[report["tribe_ref"]]["memberships"][
                member.state.being_ref
            ]
            self.assertEqual(membership["state"], "active")
            self.assertEqual(len(membership["episodes"]), 2)

            invalid = copy.deepcopy(membership["membership_event"]["payload"])
            invalid["membership_sequence"] = 2
            invalid["previous_membership_terminal_ref"] = None
            with self.assertRaisesRegex(
                RelationshipError, "invalid_tribe_membership_acceptance"
            ):
                validate_relationship_event_payload(
                    "matrix/tribe-membership-acceptance",
                    invalid,
                    author_being_ref=member.state.being_ref,
                    causal_parents=(),
                )

    def test_competing_membership_terminals_quarantine_without_winner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-terminal-fork-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            member = journey.identities["member"]
            membership = _event(
                journey, event_id=report["evidence"]["membership_event_id"]
            )
            common = {
                "tribe_ref": report["tribe_ref"],
                "founder_epoch": 0,
                "member_being_ref": member.state.being_ref,
                "membership_acceptance_ref": _ref(membership),
                "terminated_at_ms": NOW + 8,
            }
            journey.append(
                "member",
                "matrix/tribe-membership-leave",
                {
                    **common,
                    "schema": MEMBERSHIP_LEAVE_SCHEMA,
                    "reason": "member-choice",
                },
                at_ms=NOW + 8,
            )
            journey.append(
                "founder",
                "matrix/tribe-membership-expulsion",
                {
                    **common,
                    "schema": MEMBERSHIP_EXPULSION_SCHEMA,
                    "founder_being_ref": founder.state.being_ref,
                    "reason": "founder-choice",
                },
                at_ms=NOW + 8,
            )
            events = journey.store.events()
            forward = RelationshipView(
                events, at_ms=NOW + 14, card_verifier=journey.card_verifier
            )
            reverse = RelationshipView(
                list(reversed(events)),
                at_ms=NOW + 14,
                card_verifier=journey.card_verifier,
            )
            for view in (forward, reverse):
                self.assertEqual(
                    view.tribes[report["tribe_ref"]]["memberships"][
                        member.state.being_ref
                    ]["state"],
                    "forked",
                )
                snapshot = view.snapshot(report["tribe_ref"])
                self.assertEqual(
                    [row["principal_id"] for row in snapshot.value["members"]],
                    [founder.state.being_ref],
                )
                self.assertEqual(snapshot.value["grants"], [])
            self.assertEqual(forward.report(), reverse.report())

    def test_expired_cards_remove_relationship_and_snapshot_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-expiry-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            expired = journey.store.view(
                at_ms=NOW + 60_000, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                expired.relationships[report["relationship_id"]]["state"],
                "stale-card",
            )
            self.assertNotEqual(expired.grants[report["grant_id"]]["state"], "active")
            with self.assertRaisesRegex(
                RelationshipStoreError, "tribe_member_card_not_current"
            ):
                expired.snapshot(report["tribe_ref"])

    def test_origin_card_fork_quarantines_its_lane_and_dependants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-fork-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            original = next(
                event
                for event in journey.store.events()
                if event["kind"] == "matrix/relationship-card"
                and event["being_ref"] == founder.state.being_ref
            )
            payload = copy.deepcopy(original["payload"])
            payload["route_refs"] = ["dm:route:v1:fork"]
            normalized = validate_relationship_event_payload(
                "matrix/relationship-card",
                payload,
                author_being_ref=founder.state.being_ref,
                causal_parents=(),
            )
            fork = create_event(
                founder.authority,
                founder.origin,
                founder.signer,
                event_id="82000000-0000-4000-8000-000000000100",
                sequence=original["sequence"],
                previous_event_id=original["previous_event_id"],
                occurred_at_ms=NOW,
                causal_parents=(),
                kind="matrix/relationship-card",
                subject=relationship_event_subject(
                    "matrix/relationship-card", normalized
                ),
                payload=normalized,
                supersedes=None,
                sensitivity="shareable",
            )
            journey.store.ingest(fork)
            view = journey.store.view(
                at_ms=NOW + 17, card_verifier=journey.card_verifier
            )
            self.assertIn(original["event_id"], view.forked_event_ids)
            self.assertIn(fork["event_id"], view.forked_event_ids)
            self.assertNotIn(report["relationship_id"], view.relationships)
            self.assertNotIn(report["grant_id"], view.grants)

    def test_widened_root_and_child_grants_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-attenuation-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            founder = journey.identities["founder"]
            member = journey.identities["member"]
            root = _event(journey, event_id=report["evidence"]["grant_event_id"])
            child = _event(journey, event_id=report["evidence"]["child_grant_event_id"])

            widened_root = copy.deepcopy(root["payload"])
            widened_root["nonce"] = b64url(_seed("widened-root"))
            widened_root["grant_id"] = grant_id(
                nonce=widened_root["nonce"],
                relationship=widened_root["relationship_id"],
                grantor_being_ref=founder.state.being_ref,
                subject_being_ref=member.state.being_ref,
            )
            widened_root["permissions"][0]["classification"] = "secret"
            widened_root["issued_at_ms"] = NOW + 18
            widened_root_event = journey.append(
                "founder",
                "matrix/relationship-grant",
                widened_root,
                at_ms=NOW + 18,
            )

            widened_child = copy.deepcopy(child["payload"])
            widened_child["nonce"] = b64url(_seed("widened-child"))
            widened_child["grant_id"] = grant_id(
                nonce=widened_child["nonce"],
                relationship=widened_child["relationship_id"],
                grantor_being_ref=widened_child["grantor_being_ref"],
                subject_being_ref=widened_child["subject_being_ref"],
            )
            widened_child["permissions"][0]["delegable"] = True
            widened_child["permissions"][0]["remaining_delegation_depth"] = 1
            widened_child["delegation_sequence"] = 1
            widened_child["previous_delegation_event_id"] = child["event_id"]
            widened_child["issued_at_ms"] = NOW + 19
            widened_child_event = journey.append(
                "member",
                "matrix/relationship-grant",
                widened_child,
                at_ms=NOW + 19,
            )
            view = journey.store.view(
                at_ms=NOW + 20, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                view.grants[widened_root_event["payload"]["grant_id"]]["state"],
                "invalid",
            )
            self.assertEqual(
                view.grants[widened_child_event["payload"]["grant_id"]]["state"],
                "invalid",
            )

    def test_same_delegation_position_forks_lane_and_descendant(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-lane-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            child = _event(journey, event_id=report["evidence"]["child_grant_event_id"])
            member = journey.identities["member"]
            delegate = journey.identities["delegate"]
            fork_events = []
            for index in (1, 2):
                payload = copy.deepcopy(child["payload"])
                payload["nonce"] = b64url(_seed(f"lane-fork-{index}"))
                payload["grant_id"] = grant_id(
                    nonce=payload["nonce"],
                    relationship=payload["relationship_id"],
                    grantor_being_ref=member.state.being_ref,
                    subject_being_ref=delegate.state.being_ref,
                )
                payload["delegation_sequence"] = 1
                payload["previous_delegation_event_id"] = child["event_id"]
                payload["issued_at_ms"] = NOW + 18 + index
                fork_events.append(
                    journey.append(
                        "member",
                        "matrix/relationship-grant",
                        payload,
                        at_ms=NOW + 18 + index,
                    )
                )
            descendant = copy.deepcopy(child["payload"])
            descendant["nonce"] = b64url(_seed("lane-descendant"))
            descendant["grant_id"] = grant_id(
                nonce=descendant["nonce"],
                relationship=descendant["relationship_id"],
                grantor_being_ref=delegate.state.being_ref,
                subject_being_ref=member.state.being_ref,
            )
            descendant["grantor_being_ref"] = delegate.state.being_ref
            descendant["subject_being_ref"] = member.state.being_ref
            descendant["parent_grant_ref"] = {
                "event_id": fork_events[0]["event_id"],
                "event_hash": fork_events[0]["content_hash"],
            }
            descendant["delegation_sequence"] = 0
            descendant["previous_delegation_event_id"] = None
            descendant["issued_at_ms"] = NOW + 21
            descendant_event = journey.append(
                "delegate",
                "matrix/relationship-grant",
                descendant,
                at_ms=NOW + 21,
            )
            view = journey.store.view(
                at_ms=NOW + 22, card_verifier=journey.card_verifier
            )
            for event in fork_events:
                self.assertEqual(
                    view.grants[event["payload"]["grant_id"]]["state"], "forked"
                )
            self.assertEqual(
                view.grants[descendant_event["payload"]["grant_id"]]["state"],
                "forked",
            )

    def test_distinct_reauthored_acceptance_is_not_semantic_replay(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dm082-acceptance-replay-"
        ) as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            acceptance = _event(
                journey, event_id=report["evidence"]["acceptance_event_id"]
            )
            journey.append(
                "member",
                "matrix/relationship-acceptance",
                acceptance["payload"],
                at_ms=acceptance["occurred_at_ms"],
            )
            view = journey.store.view(
                at_ms=NOW + 17, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                view.relationships[report["relationship_id"]]["state"], "forked"
            )
            self.assertNotEqual(view.grants[report["grant_id"]]["state"], "active")

    def test_revocation_relinquishment_race_is_jointly_terminal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-grant-terminal-") as temporary:
            journey = _Journey(Path(temporary))
            report = journey.run()
            grant = _event(journey, event_id=report["evidence"]["grant_event_id"])
            acceptance = _event(
                journey, event_id=report["evidence"]["grant_acceptance_event_id"]
            )
            member = journey.identities["member"]
            relinquishment = journey.append(
                "member",
                "matrix/relationship-grant-revocation",
                {
                    "schema": GRANT_REVOCATION_SCHEMA,
                    "grant_id": report["grant_id"],
                    "grant_ref": _ref(grant),
                    "acceptance_ref": _ref(acceptance),
                    "actor_being_ref": member.state.being_ref,
                    "action": "relinquish",
                    "reason": "synthetic-race",
                    "revoked_at_ms": NOW + 16,
                },
                at_ms=NOW + 16,
            )
            events = journey.store.events()
            for ordered in (events, list(reversed(events))):
                view = RelationshipView(
                    ordered, at_ms=NOW + 17, card_verifier=journey.card_verifier
                )
                self.assertEqual(
                    view.grants[report["grant_id"]]["state"],
                    "revoked+relinquished",
                )
                self.assertEqual(
                    view.grants[report["child_grant_id"]]["state"],
                    "revoked+relinquished",
                )
            self.assertEqual(relinquishment["payload"]["action"], "relinquish")


class RelationshipStoreTests(unittest.TestCase):
    def test_exact_request_replay_and_changed_hash_conflict(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-idempotency-") as temporary:
            journey = _Journey(Path(temporary))
            journey.run()
            event = journey.store.events()[0]
            request_hash = hashlib.sha256(canonical_bytes(event)).hexdigest()
            before = journey.store.cursor()
            first = journey.store.ingest_idempotent(
                request_id="dm082-request-1",
                request_hash=request_hash,
                event=event,
            )
            replay = journey.store.ingest_idempotent(
                request_id="dm082-request-1",
                request_hash=request_hash,
                event=event,
            )
            self.assertEqual(first, replay)
            self.assertEqual(journey.store.cursor(), before)
            with self.assertRaisesRegex(
                RelationshipStoreError, "relationship_request_conflict"
            ):
                journey.store.ingest_idempotent(
                    request_id="dm082-request-1",
                    request_hash="0" * 64,
                    event=event,
                )

    def test_owner_only_parent_and_non_symlink_store_are_required(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-owner-") as temporary:
            root = Path(temporary)
            journey = _Journey(root / "authority")
            resolver = journey.store.authority_resolver
            open_parent = root / "open"
            open_parent.mkdir(mode=0o700)
            os.chmod(open_parent, 0o755)
            with self.assertRaisesRegex(
                RelationshipStoreError, "relationship_parent_not_owner_only"
            ):
                RelationshipStore(
                    open_parent / "relationships.sqlite3",
                    authority_resolver=resolver,
                ).initialize()

            target = root / "target.sqlite3"
            target.touch(mode=0o600)
            link = root / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaisesRegex(
                RelationshipStoreError, "relationship_store_not_owner_only"
            ):
                RelationshipStore(link, authority_resolver=resolver).initialize()

    def test_corrupt_database_fails_with_closed_store_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-corrupt-") as temporary:
            journey = _Journey(Path(temporary) / "authority")
            path = Path(temporary) / "relationships.sqlite3"
            path.write_bytes(b"not a sqlite database")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                RelationshipStoreError, "relationship_store_corrupt"
            ):
                RelationshipStore(
                    path, authority_resolver=journey.store.authority_resolver
                ).initialize()


class RelationshipServiceTests(unittest.TestCase):
    def test_authenticated_mutation_foreign_ingest_status_and_closed_denial(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="dm082-service-") as temporary:
            root = Path(temporary)
            journey = _Journey(root / "relationships")
            founder = journey.identities["founder"]
            member = journey.identities["member"]
            ledger = Ledger(
                root / "local.sqlite3",
                authority=founder.authority,
                local_origin=founder.origin,
                clock=lambda: NOW,
            )
            capability = create_capability(
                hashlib.sha256(b"dm082 relationship service").digest(),
                client_id="client:dm082",
                methods=sorted(RELATIONSHIP_METHODS),
                not_before_ms=NOW - 1,
                not_after_ms=NOW + 1_000,
            )
            service = HostedWeave(
                ledger,
                founder.signer,
                {capability.capability_id: capability},
                lambda: NOW,
                relationships=RelationshipServiceContext(
                    journey.store, journey.card_verifier
                ),
            )

            publish = create_request(
                capability,
                request_id="82000000-0000-4000-8000-000000000201",
                issued_at_ms=NOW,
                method="relationship.card.publish",
                params={"payload": _card_payload(journey, "founder")},
                nonce=b"a" * 16,
            )
            first = service.handle(publish)
            self.assertTrue(first["ok"], first)
            self.assertEqual(service.handle(publish), first)
            self.assertEqual(len(ledger.events()), 1)

            member_payload = validate_relationship_event_payload(
                "matrix/relationship-card",
                _card_payload(journey, "member"),
                author_being_ref=member.state.being_ref,
                causal_parents=(),
            )
            member_event = create_event(
                member.authority,
                member.origin,
                member.signer,
                event_id="82000000-0000-4000-8000-000000000202",
                sequence=1,
                previous_event_id=None,
                occurred_at_ms=NOW,
                causal_parents=(),
                kind="matrix/relationship-card",
                subject=relationship_event_subject(
                    "matrix/relationship-card", member_payload
                ),
                payload=member_payload,
                supersedes=None,
                sensitivity="shareable",
            )
            ingest = create_request(
                capability,
                request_id="82000000-0000-4000-8000-000000000203",
                issued_at_ms=NOW,
                method="relationship.event.ingest",
                params={"event": member_event},
                nonce=b"b" * 16,
            )
            self.assertTrue(service.handle(ingest)["ok"])

            status = create_request(
                capability,
                request_id="82000000-0000-4000-8000-000000000204",
                issued_at_ms=NOW,
                method="relationship.status",
                params={"at_ms": NOW},
                nonce=b"c" * 16,
            )
            status_response = service.handle(status)
            self.assertTrue(status_response["ok"], status_response)
            self.assertEqual(len(status_response["result"]["history"]["cards"]), 2)

            denials = []
            for index, resource in enumerate(("unknown:a", "unknown:b"), start=5):
                request = create_request(
                    capability,
                    request_id=f"82000000-0000-4000-8000-00000000020{index}",
                    issued_at_ms=NOW,
                    method="relationship.disclose",
                    params={
                        "at_ms": NOW,
                        "classification": "shareable",
                        "operation": "read",
                        "requester_being_ref": member.state.being_ref,
                        "resource_ref": resource,
                    },
                    nonce=bytes([96 + index]) * 16,
                )
                response = service.handle(request)
                self.assertTrue(response["ok"], response)
                denials.append(response["result"])
            self.assertEqual(denials[0], denials[1])
            self.assertEqual(
                denials[0],
                {
                    "schema": "dm.relationship.disclosure/v1",
                    "authorized": False,
                    "authorization": None,
                },
            )


class RelationshipRuntimeTests(RuntimeFixture):
    def test_v6_bundle_loads_relationship_store_and_dynamic_scope_provider(
        self,
    ) -> None:
        state_root, bundle, _ = self.make_bundle(state_name="relationships-v6")
        bundle.update(
            {
                "authority_history": [],
                "peer_transport": None,
                "relationships": {
                    "known_being_refs": [],
                    "store_filename": "relationships.sqlite3",
                },
                "schema": "dm.runtime.bundle/v6",
                "sources": {
                    "cas_filename": "sources.sqlite3",
                    "known_beings": [],
                },
                "species": None,
            }
        )
        bundle_path = state_root / "runtime.json"
        bundle_path.write_bytes(canonical_bytes(bundle))
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/hosted/v6/bundle.schema.json"
            ).read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(bundle)
        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        context = runtime.service.relationships
        self.assertIsNotNone(context)
        assert context is not None
        member = runtime.service.ledger.authority.manifest.member(
            self.origins["legion"]["embodiment_id"],
            self.origins["legion"]["incarnation_id"],
        )
        credential = self.credentials[member["embodiment_credential_id"]]
        payload = {
            "schema": CARD_SCHEMA,
            "card_series_id": card_series_id(self.state.being_ref),
            "sequence": 0,
            "previous_card_event_id": None,
            "being_ref": self.state.being_ref,
            "control_position": {
                "manifest_hash": self.manifest.digest,
                "embodiment_id": self.origins["legion"]["embodiment_id"],
                "incarnation_id": self.origins["legion"]["incarnation_id"],
            },
            "encryption_key": credential["body"]["encryption_key"],
            "route_refs": ["dm:route:v1:runtime"],
            "capability_refs": ["dm:capability:v1:relationship-v1"],
            "resources": [],
            "issued_at_ms": NOW,
            "expires_at_ms": NOW + 60_000,
        }
        event = runtime.service.ledger.append_local(
            kind="matrix/relationship-card",
            subject=card_series_id(self.state.being_ref),
            payload=payload,
            signer=runtime.service.signer,
            sensitivity="shareable",
            occurred_at_ms=NOW,
        )
        context.store.ingest(event)
        view = context.store.view(at_ms=NOW, card_verifier=context.card_verifier)
        self.assertTrue(view.cards[self.state.being_ref]["current"])

        collision = copy.deepcopy(bundle)
        collision["relationships"]["store_filename"] = collision["ledger"]
        bundle_path.write_bytes(canonical_bytes(collision))
        with self.assertRaisesRegex(ValueError, "runtime_filename_collision"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
