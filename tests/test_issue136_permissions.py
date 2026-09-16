"""Explicit successor authorization; no production custody or network."""

import contextlib
import copy
import tempfile
import unittest
from pathlib import Path

from daimon_matrix import identity, local_api, relationships
from daimon_matrix.synthetic_relationships import _Journey
from tests.test_dm021_identity import NOW, IdentityFixture, seed


class FixtureComplete(Exception):
    pass


class V2Journey(_Journey):
    """Reuse signed bilateral fixtures, stopping before any delivery/network."""

    def __init__(self, root):
        from dataclasses import replace
        from unittest.mock import patch

        from daimon_matrix.canonical import unb64url
        from daimon_matrix.synthetic_relationships import _identity, _seed
        from daimon_matrix.weave import BeingManifest, RootAuthority

        def v2_identity(label):
            old = _identity(label)
            body = old.credential["body"]
            credential = identity.create_embodiment_credential_v2(
                old.state,
                [_seed(f"{label}:root:{i}") for i in range(3)],
                _seed(f"{label}:signing"),
                unb64url(body["encryption_key"]["public"], length=32),
                embodiment_id=body["embodiment_id"],
                body_ref=body["body_ref"],
                purposes=body["purposes"],
                transport_principals=body["transport_principals"],
                validity={"mode": "until-revoked", "not_before_ms": 0},
            )
            incarnation = identity.create_incarnation_authorization(
                credential,
                _seed(f"{label}:signing"),
                incarnation_id=old.origin["incarnation_id"],
                incarnation_sequence=0,
                started_at_ms=0,
            )
            manifest = copy.deepcopy(dict(old.authority.manifest.value))
            manifest["embodiments"][0].update(
                embodiment_credential_id=credential["artifact_id"],
                incarnation_authorization_id=incarnation["artifact_id"],
            )
            authority = RootAuthority(
                BeingManifest.from_value(manifest),
                old.state,
                {credential["artifact_id"]: credential},
                {incarnation["artifact_id"]: incarnation},
            )
            return replace(old, credential=credential, authority=authority)

        with patch(
            "daimon_matrix.synthetic_relationships._identity", side_effect=v2_identity
        ):
            super().__init__(root)

    def card_verifier(self, card, at_ms):
        from daimon_matrix.runtime import verify_relationship_card_authority

        verify_relationship_card_authority(
            card, self.authorities[card["being_ref"]], at_ms=at_ms
        )

    def append(self, label, kind, payload, *, at_ms):
        payload = copy.deepcopy(payload)
        if kind.startswith("matrix/relationship-"):
            payload["schema"] = payload["schema"].replace("/v1", "/v2")
        if kind == "matrix/relationship-card":
            payload.pop("expires_at_ms")
            payload["validity"] = {"mode": "until-revoked", "not_before_ms": at_ms}
            payload["status"] = "active"
            for entry in payload["resources"]:
                old_ref = entry["resource_ref"]
                entry["descriptor"]["operations"] = ["messaging.read"]
                entry["resource_ref"] = relationships.resource_ref(entry["descriptor"])
                self.resource_mapping = (old_ref, entry["resource_ref"])
        if kind in {"matrix/relationship-offer", "matrix/relationship-grant"}:
            rows = payload.get("proposed_grants", [payload])
            for row in rows:
                row["validity"] = {
                    "mode": "until-revoked",
                    "not_before_ms": row.pop("not_before_ms"),
                }
                row.pop("expires_at_ms")
                for permission in row["permissions"]:
                    permission["operations"] = ["messaging.read"]
                    permission["resource_ref"] = self.resource_mapping[1]
        event = super().append(label, kind, payload, at_ms=at_ms)
        if kind == "matrix/relationship-grant-acceptance":
            raise FixtureComplete()
        return event

    def prepare(self):
        with contextlib.suppress(FixtureComplete):
            self.run()


class PermissionTests(unittest.TestCase):
    def test_v2_schema_and_public_vectors(self):
        import json

        from jsonschema import Draft202012Validator

        root = Path(__file__).resolve().parents[1]
        contracts = json.loads(
            (root / "schemas/relationships/v2/contracts.schema.json").read_text()
        )
        validator = Draft202012Validator(contracts)
        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            for event in journey.store.events():
                validator.validate(event["payload"])
            snapshot = journey.store.view(
                at_ms=NOW + 10**12, card_verifier=journey.card_verifier
            ).snapshot(
                next(
                    iter(
                        journey.store.view(
                            at_ms=NOW + 10, card_verifier=journey.card_verifier
                        ).tribes
                    )
                )
            )
            Draft202012Validator(
                json.loads(
                    (root / "schemas/relationships/v2/tribe.schema.json").read_text()
                )
            ).validate(snapshot.value)
            self.assertEqual(
                json.loads(
                    (root / "vectors/relationships/v2/issue136.json").read_text()
                )["events"],
                journey.store.events(),
            )
            self.assertEqual(
                json.loads(
                    (root / "vectors/relationships/v2/issue136.json").read_text()
                )["snapshot"],
                snapshot.value,
            )
            credential = journey.identities["founder"].credential
            self.assertEqual(
                json.loads((root / "vectors/identity/v2/issue136.json").read_text())[
                    "credential"
                ],
                credential,
            )
            Draft202012Validator(
                json.loads(
                    (
                        root / "schemas/identity/v2/embodiment-credential.schema.json"
                    ).read_text()
                )
            ).validate(credential)
        cap = local_api.create_messaging_capability(
            seed("cap"),
            client_id="test",
            methods=["messaging.inbox"],
            not_before_ms=NOW,
        )
        Draft202012Validator(
            json.loads(
                (root / "schemas/hosted/v2/local-capability.schema.json").read_text()
            )
        ).validate(cap.descriptor)

    def test_signed_v2_relationship_survives_large_clock_advance(self):
        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            view = journey.store.view(
                at_ms=NOW + 10**12, card_verifier=journey.card_verifier
            )
            self.assertEqual([row["state"] for row in view.grants.values()], ["active"])
            self.assertEqual(
                [row["state"] for row in view.relationships.values()], ["active"]
            )
            snapshot = view.snapshot(next(iter(view.tribes)))
            self.assertEqual(snapshot.value["schema"], "dm.tribe-snapshot/v2")
            self.assertEqual(
                snapshot.value["grants"][0]["validity"]["mode"], "until-revoked"
            )

    def test_actual_mixed_grants_attenuate_and_parent_revocation_cascades(self):
        from daimon_matrix.canonical import b64url
        from daimon_matrix.synthetic_relationships import _event_ref, _seed

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            events = journey.store.events()
            parent = next(e for e in events if e["kind"] == "matrix/relationship-grant")
            parent_acceptance = next(
                e for e in events if e["kind"] == "matrix/relationship-grant-acceptance"
            )
            child = copy.deepcopy(parent["payload"])
            child["schema"] = "dm.relationship.grant/v1"
            child.pop("validity")
            child.update(
                not_before_ms=NOW + 10,
                expires_at_ms=NOW + 1000,
                issued_at_ms=NOW + 10,
                parent_grant_ref=_event_ref(parent),
                nonce=b64url(_seed("mixed-child")),
                grantor_being_ref=parent["payload"]["subject_being_ref"],
                subject_being_ref=parent["payload"]["grantor_being_ref"],
            )
            child["permissions"][0].update(
                delegable=False, remaining_delegation_depth=0
            )
            child["grant_id"] = relationships.grant_id(
                nonce=child["nonce"],
                relationship=child["relationship_id"],
                grantor_being_ref=child["grantor_being_ref"],
                subject_being_ref=child["subject_being_ref"],
            )
            event = _Journey.append(
                journey, "member", "matrix/relationship-grant", child, at_ms=NOW + 10
            )
            _Journey.append(
                journey,
                "founder",
                "matrix/relationship-grant-acceptance",
                {
                    "schema": "dm.relationship.grant-acceptance/v1",
                    "grant_id": child["grant_id"],
                    "grant_ref": _event_ref(event),
                    "relationship_id": child["relationship_id"],
                    "grantor_being_ref": child["grantor_being_ref"],
                    "subject_being_ref": child["subject_being_ref"],
                    "accepted_at_ms": NOW + 11,
                },
                at_ms=NOW + 11,
            )
            view = journey.store.view(
                at_ms=NOW + 12, card_verifier=journey.card_verifier
            )
            self.assertEqual(view.grants[child["grant_id"]]["state"], "active")
            late = journey.store.view(
                at_ms=NOW + 1000, card_verifier=journey.card_verifier
            )
            self.assertEqual(late.grants[child["grant_id"]]["state"], "expired")
            self.assertEqual(
                late.grants[parent["payload"]["grant_id"]]["state"], "active"
            )
            _Journey.append(
                journey,
                "founder",
                "matrix/relationship-grant-revocation",
                {
                    "schema": "dm.relationship.grant-revocation/v2",
                    "grant_id": parent["payload"]["grant_id"],
                    "grant_ref": _event_ref(parent),
                    "acceptance_ref": _event_ref(parent_acceptance),
                    "actor_being_ref": parent["being_ref"],
                    "action": "revoke",
                    "reason": "manual",
                    "revoked_at_ms": NOW + 100,
                },
                at_ms=NOW + 100,
            )
            with journey.store.authorization_view(
                at_ms=NOW + 12, card_verifier=journey.card_verifier
            ) as view:
                self.assertEqual(view.grants[child["grant_id"]]["state"], "revoked")

    def test_indefinite_child_under_real_finite_v1_parent_is_invalid(self):
        from daimon_matrix.canonical import b64url
        from daimon_matrix.synthetic_relationships import _event_ref, _seed

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            original = next(
                e
                for e in journey.store.events()
                if e["kind"] == "matrix/relationship-grant"
            )

            def add(payload, grantor, subject, label, at_ms):
                payload["nonce"] = b64url(_seed(label))
                payload["grant_id"] = relationships.grant_id(
                    nonce=payload["nonce"],
                    relationship=payload["relationship_id"],
                    grantor_being_ref=payload["grantor_being_ref"],
                    subject_being_ref=payload["subject_being_ref"],
                )
                event = _Journey.append(
                    journey, grantor, "matrix/relationship-grant", payload, at_ms=at_ms
                )
                _Journey.append(
                    journey,
                    subject,
                    "matrix/relationship-grant-acceptance",
                    {
                        "schema": "dm.relationship.grant-acceptance/v2",
                        "grant_id": payload["grant_id"],
                        "grant_ref": _event_ref(event),
                        "relationship_id": payload["relationship_id"],
                        "grantor_being_ref": payload["grantor_being_ref"],
                        "subject_being_ref": payload["subject_being_ref"],
                        "accepted_at_ms": at_ms + 1,
                    },
                    at_ms=at_ms + 1,
                )
                return event

            finite = copy.deepcopy(original["payload"])
            finite.pop("validity")
            finite.update(
                schema="dm.relationship.grant/v1",
                not_before_ms=NOW + 10,
                expires_at_ms=NOW + 1000,
                issued_at_ms=NOW + 10,
            )
            parent = add(finite, "founder", "member", "finite-parent", NOW + 10)
            child = copy.deepcopy(original["payload"])
            child.update(
                parent_grant_ref=_event_ref(parent),
                issued_at_ms=NOW + 12,
                validity={"mode": "until-revoked", "not_before_ms": NOW + 12},
                grantor_being_ref=finite["subject_being_ref"],
                subject_being_ref=finite["grantor_being_ref"],
            )
            child["permissions"][0].update(
                delegable=False, remaining_delegation_depth=0
            )
            event = add(child, "member", "founder", "indefinite-child", NOW + 12)
            view = journey.store.view(
                at_ms=NOW + 15, card_verifier=journey.card_verifier
            )
            self.assertEqual(
                view.grants[parent["payload"]["grant_id"]]["state"], "active"
            )
            self.assertEqual(
                view.grants[event["payload"]["grant_id"]]["state"], "invalid"
            )

    def test_authenticated_malformed_grants_leave_store_unchanged(self):
        import hashlib

        from daimon_matrix.canonical import canonical_bytes
        from daimon_matrix.relationship_store import RelationshipStoreError

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            before = journey.store.events()
            grant = next(e for e in before if e["kind"] == "matrix/relationship-grant")
            for operations in (None, [["messaging.read"]], {}, [1], [None]):
                malformed = copy.deepcopy(grant)
                malformed["payload"]["permissions"][0]["operations"] = operations
                core = {
                    k: v
                    for k, v in malformed.items()
                    if k not in {"content_hash", "signature"}
                }
                malformed["content_hash"] = hashlib.sha256(
                    canonical_bytes(core)
                ).hexdigest()
                malformed["signature"] = journey.identities["founder"].signer.signature(
                    malformed["content_hash"]
                )
                with (
                    self.subTest(operations=operations),
                    self.assertRaises(RelationshipStoreError),
                ):
                    journey.store.ingest(malformed)
                self.assertEqual(journey.store.events(), before)

    def test_membership_reentry_does_not_revive_old_v2_grant(self):
        from daimon_matrix.canonical import b64url
        from daimon_matrix.synthetic_relationships import _event_ref, _seed

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            events = journey.store.events()
            membership = next(
                e for e in events if e["kind"] == "matrix/tribe-membership-acceptance"
            )
            invitation = next(
                e for e in events if e["kind"] == "matrix/tribe-invitation"
            )
            left = _Journey.append(
                journey,
                "member",
                "matrix/tribe-membership-leave",
                {
                    "schema": relationships.MEMBERSHIP_LEAVE_SCHEMA,
                    "tribe_ref": membership["payload"]["tribe_ref"],
                    "founder_epoch": 0,
                    "member_being_ref": membership["being_ref"],
                    "membership_acceptance_ref": _event_ref(membership),
                    "reason": "manual",
                    "terminated_at_ms": NOW + 100,
                },
                at_ms=NOW + 100,
            )
            invited = copy.deepcopy(invitation["payload"])
            invited.update(
                issued_at_ms=NOW + 101,
                expires_at_ms=NOW + 500,
                nonce=b64url(_seed("reentry")),
            )
            invited["invitation_id"] = relationships.invitation_id(
                tribe=invited["tribe_ref"],
                founder_epoch=0,
                invitee_being_ref=invited["invitee_being_ref"],
                nonce=invited["nonce"],
            )
            event = _Journey.append(
                journey, "founder", "matrix/tribe-invitation", invited, at_ms=NOW + 101
            )
            accepted = {
                **membership["payload"],
                "membership_sequence": 1,
                "previous_membership_terminal_ref": _event_ref(left),
                "invitation_ref": _event_ref(event),
                "accepted_at_ms": NOW + 102,
            }
            _Journey.append(
                journey,
                "member",
                "matrix/tribe-membership-acceptance",
                accepted,
                at_ms=NOW + 102,
            )
            with journey.store.authorization_view(
                at_ms=NOW + 103, card_verifier=journey.card_verifier
            ) as view:
                self.assertEqual(
                    view.tribes[invited["tribe_ref"]]["memberships"][
                        membership["being_ref"]
                    ]["state"],
                    "active",
                )
                self.assertNotIn(
                    "active", [row["state"] for row in view.grants.values()]
                )

    def test_v2_malformed_operations_and_finite_limits_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            view = journey.store.view(
                at_ms=NOW + 10, card_verifier=journey.card_verifier
            )
            snapshot = view.snapshot(next(iter(view.tribes))).value
            for malformed in (
                None,
                [["messaging.read"]],
                {},
                [None],
                [1],
                "messaging.read",
            ):
                changed = copy.deepcopy(snapshot)
                changed["grants"][0]["operations"] = malformed
                with (
                    self.subTest(operations=malformed),
                    self.assertRaises(relationships.RelationshipError),
                ):
                    relationships.VerifiedTribeSnapshot.from_value(
                        changed, verifier=lambda _: None
                    )
            event = next(
                e
                for e in journey.store.events()
                if e["kind"] == "matrix/relationship-grant"
            )
            payload = copy.deepcopy(event["payload"])
            payload["permissions"][0]["operations"] = ["read"]
            for end in (NOW + relationships.MAX_GRANT_LIFETIME_MS + 1, NOW + 1):
                payload["validity"] = {
                    "mode": "finite",
                    "not_before_ms": NOW,
                    "not_after_ms": end,
                }
                with (
                    self.subTest(end=end),
                    self.assertRaises(relationships.RelationshipError),
                ):
                    relationships.validate_relationship_event_payload(
                        event["kind"],
                        payload,
                        author_being_ref=event["being_ref"],
                        causal_parents=[],
                    )

    def test_current_authorization_serializes_other_writers_and_missing_state_fails(
        self,
    ):
        import sqlite3

        from daimon_matrix.relationship_store import (
            RelationshipStore,
            RelationshipStoreError,
        )

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            other = sqlite3.connect(journey.store.path, timeout=0)
            try:
                with journey.store.authorization_view(
                    at_ms=NOW + 10, card_verifier=journey.card_verifier
                ) as view:
                    self.assertIn("active", [g["state"] for g in view.grants.values()])
                    with self.assertRaises(sqlite3.OperationalError):
                        other.execute("BEGIN IMMEDIATE")
                other.execute("BEGIN IMMEDIATE")
                other.rollback()
            finally:
                other.close()
            missing = RelationshipStore(
                Path(temporary) / "missing.sqlite3",
                authority_resolver=journey.store.authority_resolver,
            )
            with (
                self.assertRaises(RelationshipStoreError),
                missing.authorization_view(
                    at_ms=NOW + 10, card_verifier=journey.card_verifier
                ),
            ):
                pass
            self.assertFalse(missing.path.exists())

    def test_current_authority_revoke_survives_restart_and_clock_rollback(self):
        from daimon_matrix.relationship_store import RelationshipStore

        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            events = journey.store.events()
            grant = next(e for e in events if e["kind"] == "matrix/relationship-grant")
            acceptance = next(
                e for e in events if e["kind"] == "matrix/relationship-grant-acceptance"
            )

            def ref(e):
                return {"event_id": e["event_id"], "event_hash": e["content_hash"]}

            _Journey.append(
                journey,
                "founder",
                "matrix/relationship-grant-revocation",
                {
                    "schema": "dm.relationship.grant-revocation/v2",
                    "grant_id": grant["payload"]["grant_id"],
                    "grant_ref": ref(grant),
                    "acceptance_ref": ref(acceptance),
                    "actor_being_ref": grant["being_ref"],
                    "action": "revoke",
                    "reason": "manual",
                    "revoked_at_ms": NOW + 100,
                },
                at_ms=NOW + 100,
            )
            store = RelationshipStore(
                journey.store.path, authority_resolver=journey.store.authority_resolver
            )
            with store.authorization_view(
                at_ms=NOW + 10, card_verifier=journey.card_verifier
            ) as view:
                self.assertEqual(
                    view.grants[grant["payload"]["grant_id"]]["state"], "revoked"
                )
            historical = store.view(at_ms=NOW + 10, card_verifier=journey.card_verifier)
            self.assertEqual(
                historical.grants[grant["payload"]["grant_id"]]["state"], "active"
            )

    def test_v2_card_withdrawal_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            journey = V2Journey(Path(temporary))
            journey.prepare()
            card = next(
                e
                for e in journey.store.events()
                if e["kind"] == "matrix/relationship-card"
                and e["being_ref"] == journey.identities["founder"].state.being_ref
            )
            payload = {
                **card["payload"],
                "sequence": 1,
                "previous_card_event_id": card["event_id"],
                "status": "withdrawn",
                "issued_at_ms": NOW + 100,
                "validity": {"mode": "until-revoked", "not_before_ms": NOW + 100},
            }
            withdrawn = _Journey.append(
                journey, "founder", "matrix/relationship-card", payload, at_ms=NOW + 100
            )
            downgrade = {
                k: v for k, v in payload.items() if k not in {"validity", "status"}
            }
            downgrade.update(
                schema=relationships.CARD_SCHEMA,
                sequence=2,
                previous_card_event_id=withdrawn["event_id"],
                issued_at_ms=NOW + 101,
                expires_at_ms=NOW + 500,
            )
            _Journey.append(
                journey,
                "founder",
                "matrix/relationship-card",
                downgrade,
                at_ms=NOW + 101,
            )
            with journey.store.authorization_view(
                at_ms=NOW + 110, card_verifier=journey.card_verifier
            ) as view:
                self.assertIsNone(view.cards[card["being_ref"]]["current"])
            with journey.store.authorization_view(
                at_ms=NOW + 10, card_verifier=journey.card_verifier
            ) as view:
                self.assertIsNone(view.cards[card["being_ref"]]["current"])
                self.assertNotIn("active", [g["state"] for g in view.grants.values()])

    def test_v2_capability_is_messaging_only_and_preserves_request_freshness(self):
        cap = local_api.create_messaging_capability(
            seed("cap"),
            client_id="test",
            methods=["messaging.inbox"],
            not_before_ms=NOW,
        )
        far = NOW + 10**12
        request = local_api.create_request(
            cap,
            request_id="12345678-1234-4234-8234-123456789012",
            issued_at_ms=far,
            method="messaging.inbox",
            params={},
        )
        local_api.authenticate_request(request, cap, now_ms=far)
        with self.assertRaises(local_api.LocalApiError):
            local_api.authenticate_request(request, cap, now_ms=far + 31_000)
        with self.assertRaises(local_api.LocalApiError):
            local_api.create_messaging_capability(
                seed("cap"),
                client_id="test",
                methods=["runtime.stop"],
                not_before_ms=NOW,
            )
        revoked = local_api.create_messaging_capability(
            seed("cap"),
            client_id="test",
            methods=["messaging.inbox"],
            not_before_ms=NOW,
            status="revoked",
        )
        with self.assertRaises(local_api.LocalApiError):
            local_api.authenticate_request(request, revoked, now_ms=far)

    def test_validity_algebra_is_closed_and_attenuates(self):
        unlimited = {"mode": "until-revoked", "not_before_ms": NOW}
        finite = {"mode": "finite", "not_before_ms": NOW, "not_after_ms": NOW + 1}
        self.assertFalse(identity.validity_attenuates(unlimited, finite))
        self.assertTrue(identity.validity_attenuates(finite, unlimited))
        self.assertFalse(identity.validity_contains(finite, NOW + 1))
        for bad in (
            None,
            {**unlimited, "not_after_ms": None},
            {**unlimited, "not_before_ms": True},
            {**unlimited, "not_before_ms": 2**53},
            {"mode": "forever"},
        ):
            with self.subTest(bad=bad), self.assertRaises(identity.VerificationError):
                identity.validate_validity(bad)

    def test_v2_credential_large_clock_and_v1_expiry(self):
        fixture = IdentityFixture()
        fixture.setUp()
        old = fixture.credential("local")
        with self.assertRaises(identity.VerificationError):
            identity.create_embodiment_credential_v2(
                fixture.state,
                fixture.root,
                seed("local-signing"),
                identity.x25519_public(seed("local-encryption")),
                embodiment_id=old["body"]["embodiment_id"],
                body_ref=old["body"]["body_ref"],
                purposes=["weave"],
                validity={"mode": "until-revoked", "not_before_ms": NOW},
            )
        new = identity.create_embodiment_credential_v2(
            fixture.state,
            fixture.root,
            seed("local-signing"),
            identity.x25519_public(seed("local-encryption")),
            embodiment_id=old["body"]["embodiment_id"],
            body_ref=old["body"]["body_ref"],
            purposes=old["body"]["purposes"],
            validity={"mode": "until-revoked", "not_before_ms": NOW},
            transport_principals=old["body"]["transport_principals"],
        )
        assert new["schema"] == "dm.identity.artifact/v2"
        assert new["artifact_id"].startswith("dm:identity:v2:")
        identity.verify_embodiment_credential(new, fixture.state, at_ms=NOW + 10**12)
        with self.assertRaisesRegex(identity.VerificationError, "validity"):
            identity.verify_embodiment_credential(
                old, fixture.state, at_ms=NOW + 10**12
            )
        for field in ("signatures", "acceptance"):
            changed = copy.deepcopy(new)
            if field == "signatures":
                changed["signatures"] = [
                    s
                    for s in changed["signatures"]
                    if s["role"] != "root-authorization"
                ]
            else:
                changed["signatures"] = [
                    s
                    for s in changed["signatures"]
                    if s["role"] != "embodiment-acceptance"
                ]
            with (
                self.subTest(field=field),
                self.assertRaises(identity.VerificationError),
            ):
                identity.verify_embodiment_credential(changed, fixture.state, at_ms=NOW)
        revocation = identity.create_revocation(
            fixture.state,
            fixture.root,
            embodiment_id=old["body"]["embodiment_id"],
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked_state = identity.verify_successor(revocation, fixture.state)
        with self.assertRaises(identity.VerificationError):
            identity.verify_embodiment_credential(
                new, revoked_state, at_ms=NOW + 10**12
            )
        changed = copy.deepcopy(new)
        changed["schema"] = "dm.identity.artifact/v1"
        with self.assertRaises(identity.VerificationError):
            identity.verify_embodiment_credential(changed, fixture.state, at_ms=NOW)
