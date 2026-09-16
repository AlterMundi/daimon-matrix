"""Signed same-embodiment succession and genuine hosted startup."""

import copy

from daimon_matrix import authority_epochs, identity, local_api, runtime
from daimon_matrix.canonical import canonical_bytes, unb64url
from daimon_matrix.operator_rebirth import authority_from_runtime_bundle
from daimon_matrix.sealed import (
    DisclosureAuthorization,
    RecipientTarget,
    SealedDeliveryError,
    open_event,
    recipient_descriptor,
    seal_event,
    sender_descriptor,
)
from daimon_matrix.weave import BeingManifest, RootAuthority
from tests.test_dm024_runtime import NOW, PASSWORD, RuntimeFixture
from tests.test_dm051_sealed import SealedFixture


def successor(fixture, *, issued_at_ms=NOW + 10, purposes=None):
    origin = fixture.origins["legion"]
    previous = fixture.authority
    row = previous.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    old = previous.credentials[row["embodiment_credential_id"]]
    body = old["body"]
    new = identity.create_embodiment_credential_v2(
        previous.state,
        fixture.root_seeds,
        fixture.signing_seeds["legion"],
        unb64url(body["encryption_key"]["public"], length=32),
        embodiment_id=body["embodiment_id"],
        body_ref=body["body_ref"],
        purposes=body["purposes"] if purposes is None else purposes,
        revocation_generation=body["revocation_generation"],
        transport_principals=body["transport_principals"],
        validity={"mode": "until-revoked", "not_before_ms": body["valid_from_ms"]},
    )
    old_incarnation = previous.incarnations[row["incarnation_authorization_id"]]["body"]
    authorization = identity.create_incarnation_authorization(
        new,
        fixture.signing_seeds["legion"],
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=old_incarnation["incarnation_sequence"],
        started_at_ms=old_incarnation["started_at_ms"],
    )
    manifest = copy.deepcopy(previous.manifest.value)
    manifest["revision"] += 1
    for member in manifest["embodiments"]:
        if member == row:
            member["embodiment_credential_id"] = new["artifact_id"]
            member["incarnation_authorization_id"] = authorization["artifact_id"]
    active = RootAuthority(
        BeingManifest.from_value(manifest),
        previous.state,
        {**previous.credentials, new["artifact_id"]: new},
        {**previous.incarnations, authorization["artifact_id"]: authorization},
    )
    transition = authority_epochs.create_credential_succession(
        previous,
        active,
        embodiment_id=origin["embodiment_id"],
        incarnation_id=origin["incarnation_id"],
        migration_id="issue136-test",
        issued_at_ms=issued_at_ms,
        root_seeds=fixture.root_seeds,
        signing_seed=fixture.signing_seeds["legion"],
    )
    return active, transition


class MigratedSealedTests(SealedFixture):
    def test_v2_envelope_keeps_finite_transport_deadline(self):
        from daimon_matrix.weave import create_event

        active, _transition = successor(self)
        origin = self.origins["legion"]
        far = NOW + 10**12
        event = create_event(
            active,
            origin,
            self.signers["legion"],
            event_id="12345678-1234-4234-8234-123456789012",
            sequence=1,
            previous_event_id=None,
            occurred_at_ms=far,
            causal_parents=(),
            kind="experience.observed",
            subject="indefinite",
            payload={"summary": "fresh"},
            sensitivity="shareable",
        )
        credential_id = active.manifest.member(
            origin["embodiment_id"], origin["incarnation_id"]
        )["embodiment_credential_id"]
        target = RecipientTarget(active, credential_id)
        authorization = DisclosureAuthorization.synthetic(
            event=event,
            sender=sender_descriptor(event, active, at_ms=far),
            recipients=[recipient_descriptor(target, at_ms=far)],
            evidence_hash="a" * 64,
            authorized_at_ms=far,
            expires_at_ms=far + 60_000,
            authorization_id="12345678-1234-4234-8234-123456789013",
        )
        raw = seal_event(
            event,
            sender_authority=active,
            recipients=[target],
            authorization=authorization,
            custody=self.custodies["legion"],
            issued_at_ms=far,
            expires_at_ms=far + 30_000,
        )
        kwargs = dict(
            sender_authority=active,
            local_target=target,
            recipient_targets=[target],
            authorization=authorization,
            custody=self.custodies["legion"],
        )
        self.assertEqual(open_event(raw, at_ms=far + 1, **kwargs), event)
        with self.assertRaises(SealedDeliveryError):
            open_event(raw, at_ms=far + 30_001, **kwargs)


class MigrationTests(RuntimeFixture):
    def test_expired_predecessor_requires_explicit_consent_without_widening(self):
        active, transition = successor(self, issued_at_ms=NOW + 10**12)
        authority_epochs.verify_credential_succession(
            transition, self.authority, active
        )
        with self.assertRaises(authority_epochs.AuthorityEpochError):
            successor(self, purposes=["messages", "new-authority"])
        for field in ("signatures", "acceptance"):
            modified = copy.deepcopy(transition)
            modified[field] = [] if field == "signatures" else {}
            with (
                self.subTest(field=field),
                self.assertRaises(authority_epochs.AuthorityEpochError),
            ):
                authority_epochs.verify_credential_succession(
                    modified, self.authority, active
                )

    def test_current_revocations_cannot_be_dropped_by_succession(self):
        revoked = identity.create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id="other-retired-body",
            cutoff_incarnation_sequence=2,
            revocation_generation=1,
        )
        state = identity.verify_successor(revoked, self.state)
        manifest = {**self.manifest.value, "control_head": state.head}
        self.authority = RootAuthority(
            BeingManifest.from_value(manifest),
            state,
            self.credentials,
            self.incarnations,
        )
        active, transition = successor(self)
        self.assertEqual(active.state.revocations, state.revocations)
        restored_manifest = {**active.manifest.value, "control_head": self.state.head}
        # Incompatible credential/control provenance must reject before
        # a transition can bless it.
        with self.assertRaises(ValueError):
            restored = RootAuthority(
                BeingManifest.from_value(restored_manifest),
                self.state,
                active.credentials,
                active.incarnations,
            )
            authority_epochs.verify_credential_succession(
                transition, self.authority, restored
            )

    def test_same_incarnation_successor_and_history_tamper(self):
        active, transition = successor(self)
        history = authority_epochs.RootHistoryAuthority(
            active, [self.authority], [transition]
        )
        self.assertEqual(
            history.active.manifest.value["embodiments"][0]["incarnation_id"],
            self.manifest.value["embodiments"][0]["incarnation_id"],
        )
        for field in (
            "migration_id",
            "previous_manifest_hash",
            "successor_credential_id",
        ):
            tampered = copy.deepcopy(transition)
            tampered[field] = "wrong"
            with (
                self.subTest(field=field),
                self.assertRaises(authority_epochs.AuthorityEpochError),
            ):
                authority_epochs.RootHistoryAuthority(
                    active, [self.authority], [tampered]
                )

    def test_v2_card_checks_current_dependency_and_retains_historical_pin(self):
        active, transition = successor(self)
        history = authority_epochs.RootHistoryAuthority(
            active, [self.authority], [transition]
        )
        origin = self.origins["legion"]
        old_row = self.manifest.member(
            origin["embodiment_id"], origin["incarnation_id"]
        )
        card = {
            "schema": "dm.relationship.card/v2",
            "being_ref": self.state.being_ref,
            "issued_at_ms": NOW,
            "control_position": {
                "manifest_hash": self.manifest.digest,
                "embodiment_id": origin["embodiment_id"],
                "incarnation_id": origin["incarnation_id"],
            },
            "encryption_key": self.credentials[old_row["embodiment_credential_id"]][
                "body"
            ]["encryption_key"],
        }
        runtime.verify_relationship_card_authority(card, history, at_ms=NOW + 10**12)
        with self.assertRaises(ValueError):
            runtime.verify_relationship_card_authority(card, self.authority, at_ms=NOW)
        altered = copy.deepcopy(card)
        altered["control_position"]["manifest_hash"] = "a" * 64
        with self.assertRaises(ValueError):
            runtime.verify_relationship_card_authority(
                altered, history, at_ms=NOW + 10**12
            )

    def test_v8_restart_after_capability_and_old_credential_expiry(self):
        state_root, bundle, cap = self.make_bundle()
        active, transition = successor(self)
        bundle.update(
            schema="dm.runtime.bundle/v8",
            manifest=active.manifest.value,
            credentials=list(active.credentials.values()),
            incarnations=list(active.incarnations.values()),
            authority_history=[
                {"manifest": self.manifest.value, "successor": transition}
            ],
        )
        self.assertEqual(authority_from_runtime_bundle(bundle), active)
        import json
        from pathlib import Path

        from jsonschema import Draft202012Validator

        repository = Path(__file__).resolve().parents[1]
        for relative, value in [
            ("schemas/hosted/v8/bundle.schema.json", bundle),
            ("schemas/weave/v2/credential-succession.schema.json", transition),
            ("schemas/weave/v1/root-manifest.schema.json", active.manifest.value),
        ]:
            Draft202012Validator(
                json.loads((repository / relative).read_text())
            ).validate(value)
        path = state_root / "runtime.json"
        path.write_bytes(canonical_bytes(bundle))
        custody_before = (state_root / "custody.json").read_bytes()
        far = NOW + 10**12
        for _ in range(2):
            loaded = runtime.load_runtime(
                state_root,
                "runtime.json",
                password_reader=lambda: bytearray(PASSWORD),
                clock=lambda: far,
            )
            self.assertEqual(
                loaded.service.ledger.authority.manifest.digest, active.manifest.digest
            )
        self.assertEqual((state_root / "custody.json").read_bytes(), custody_before)
        with self.assertRaises(local_api.LocalApiError):
            local_api.create_request(
                cap,
                request_id="12345678-1234-4234-8234-123456789012",
                issued_at_ms=far,
                method=cap.methods[0],
                params={},
            )
        bundle["schema"] = "dm.runtime.bundle/v7"
        path.write_bytes(canonical_bytes(bundle))
        with self.assertRaises(runtime.RuntimeError):
            runtime.load_runtime(
                state_root,
                "runtime.json",
                password_reader=lambda: bytearray(PASSWORD),
                clock=lambda: far,
            )
