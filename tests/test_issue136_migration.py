"""Signed same-embodiment succession and genuine hosted startup."""

import copy
import tempfile
from pathlib import Path

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


class IndependentSuccessionTests(RuntimeFixture):
    def test_dual_consent_wrong_root_unknown_fields_replay_missing_predecessor(self):
        from tests.test_dm021_identity import seed

        active, transition = successor(self)
        origin = self.origins["legion"]
        kwargs = dict(
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            migration_id="independent-negative",
            issued_at_ms=NOW + 10,
            root_seeds=self.root_seeds,
            signing_seed=self.signing_seeds["legion"],
        )
        authority_epochs.RootHistoryAuthority(active, [self.authority], [transition])
        for overrides in [
            {"root_seeds": [seed("unrelated-root")]},
            {"root_seeds": self.root_seeds[:1]},
            {"signing_seed": seed("unrelated-embodiment")},
        ]:
            with self.subTest(overrides=list(overrides)), self.assertRaises(ValueError):
                authority_epochs.create_credential_succession(
                    self.authority, active, **{**kwargs, **overrides}
                )
        with self.assertRaises(ValueError):
            authority_epochs.verify_credential_succession(
                {**transition, "unknown": True}, self.authority, active
            )
        with self.assertRaises(ValueError):
            authority_epochs.RootHistoryAuthority(
                active, [self.authority, active], [transition, transition]
            )
        with self.assertRaises(ValueError):
            authority_epochs.RootHistoryAuthority(active, [], [transition])
        # Missing historical credential must not be recreated or silently skipped.
        with self.assertRaises((ValueError, KeyError)):
            incomplete = RootAuthority(
                self.authority.manifest,
                self.authority.state,
                {},
                self.authority.incarnations,
            )
            authority_epochs.verify_credential_succession(
                transition, incomplete, active
            )

    def test_revoked_predecessor_cannot_receive_succession(self):
        successor(self)
        old = self.authority
        origin = self.origins["legion"]
        revocation = identity.create_revocation(
            self.state,
            self.root_seeds,
            embodiment_id=origin["embodiment_id"],
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked = identity.verify_successor(revocation, self.state)
        with self.assertRaises(ValueError):
            self.authority = RootAuthority(
                BeingManifest.from_value(
                    {**old.manifest.value, "control_head": revoked.head}
                ),
                revoked,
                old.credentials,
                old.incarnations,
            )
            successor(self)

    def test_rotated_root_requires_current_threshold(self):
        from tests.test_dm021_identity import seed

        old = self.authority
        old_roots = self.root_seeds
        new_roots = [
            seed("independent-rotated-root-0"),
            seed("independent-rotated-root-1"),
        ]
        rotation = identity.create_root_rotation(
            self.state,
            old_roots,
            new_roots,
            2,
            carry_forward_credentials=list(old.credentials),
        )
        state = identity.verify_successor(rotation, self.state)
        self.authority = RootAuthority(
            BeingManifest.from_value(
                {**old.manifest.value, "control_head": state.head}
            ),
            state,
            old.credentials,
            old.incarnations,
        )
        self.root_seeds = new_roots
        active, transition = successor(self)
        authority_epochs.verify_credential_succession(
            transition, self.authority, active
        )
        origin = self.origins["legion"]
        with self.assertRaises(ValueError):
            authority_epochs.create_credential_succession(
                self.authority,
                active,
                embodiment_id=origin["embodiment_id"],
                incarnation_id=origin["incarnation_id"],
                migration_id="stale-root",
                issued_at_ms=NOW + 10,
                root_seeds=old_roots,
                signing_seed=self.signing_seeds["legion"],
            )

    def migrated_bundle(self):
        root, bundle, cap = self.make_bundle()
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
        return root, bundle, cap, active

    def test_v8_expired_admin_request_rejected_by_server_not_just_builder(self):
        root, bundle, cap, _active = self.migrated_bundle()
        far = NOW + 10**12
        req = local_api.create_request(
            cap,
            request_id="12345678-1234-4234-8234-123456789019",
            issued_at_ms=NOW,
            method="runtime.status",
            params={},
        )
        # Builder at valid time is a positive control; expiry still applies
        # even when request freshness is waived.
        local_api.authenticate_request(req, cap, now_ms=NOW)
        with self.assertRaises(local_api.LocalApiError):
            local_api.authenticate_request(req, cap, now_ms=far, allow_stale=True)
        (root / "runtime.json").write_bytes(canonical_bytes(bundle))
        loaded = runtime.load_runtime(
            root,
            "runtime.json",
            password_reader=lambda: bytearray(PASSWORD),
            clock=lambda: far,
        )
        with self.assertRaisesRegex(local_api.LocalApiError, "authentication_failed"):
            loaded.service.handle(req)

    def test_established_runtime_rejects_missing_succession_history(self):
        root, bundle, _cap = self.make_bundle()
        runtime.load_runtime(
            root,
            "runtime.json",
            password_reader=lambda: bytearray(PASSWORD),
            clock=lambda: NOW,
        )
        active, transition = successor(self)
        bundle.update(
            schema="dm.runtime.bundle/v8",
            manifest=active.manifest.value,
            credentials=list(active.credentials.values()),
            incarnations=list(active.incarnations.values()),
        )
        (root / "runtime.json").write_bytes(canonical_bytes(bundle))
        from daimon_matrix.ledger import LedgerStateError

        with self.assertRaisesRegex(LedgerStateError, "ledger_metadata_mismatch"):
            runtime.load_runtime(
                root,
                "runtime.json",
                password_reader=lambda: bytearray(PASSWORD),
                clock=lambda: NOW + 10,
            )
        bundle["authority_history"] = [
            {"manifest": self.manifest.value, "successor": transition}
        ]
        (root / "runtime.json").write_bytes(canonical_bytes(bundle))
        loaded = runtime.load_runtime(
            root,
            "runtime.json",
            password_reader=lambda: bytearray(PASSWORD),
            clock=lambda: NOW + 10,
        )
        self.assertEqual(
            loaded.service.ledger.authority.manifest.digest, active.manifest.digest
        )

    def test_v8_known_peer_mixed_historical_chain_schema_runtime_parity(self):
        import json
        from types import SimpleNamespace

        from jsonschema import Draft202012Validator

        from daimon_matrix.synthetic_relationships import _identity, _seed

        root, bundle, _cap, _active = self.migrated_bundle()
        old = _identity("founder")
        peer, transition = successor(
            SimpleNamespace(
                authority=old.authority,
                origins={"legion": old.origin},
                root_seeds=[_seed(f"founder:root:{i}") for i in range(3)],
                signing_seeds={"legion": _seed("founder:signing")},
            )
        )
        genesis = identity.create_synthetic_genesis_in_process(
            [_seed(f"founder:root:{i}") for i in range(3)],
            2,
            [_seed(f"founder:recovery:{i}") for i in range(3)],
            2,
            created_at_ms=0,
            nonce=_seed("founder:being"),
        )
        peer_bundle = {
            "authority_history": [
                {"manifest": old.authority.manifest.value, "successor": transition}
            ],
            "control_artifacts": [genesis],
            "control_head": peer.state.head,
            "credentials": list(peer.credentials.values()),
            "incarnations": list(peer.incarnations.values()),
            "ledger_filename": "peer-ledger.sqlite",
            "manifest": peer.manifest.value,
        }
        bundle["sources"] = {
            "cas_filename": "source-cas.sqlite",
            "known_beings": [peer_bundle],
        }
        bundle["relationships"] = {
            "known_being_refs": [peer.state.being_ref],
            "store_filename": "rels.sqlite",
        }
        validator = Draft202012Validator(
            json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas/hosted/v8/bundle.schema.json"
                ).read_text()
            )
        )
        validator.validate(bundle)
        self.assertEqual(
            {c["schema"] for c in peer_bundle["credentials"]},
            {"dm.identity.artifact/v1", "dm.identity.artifact/v2"},
        )
        (root / "runtime.json").write_bytes(canonical_bytes(bundle))
        loaded = runtime.load_runtime(
            root,
            "runtime.json",
            password_reader=lambda: bytearray(PASSWORD),
            clock=lambda: NOW + 10,
        )
        context = loaded.service.relationships
        assert context is not None and context.authority_resolver is not None
        self.assertEqual(context.authority_resolver(peer.state.being_ref), peer)
        assert context.store.authority_resolver is not None
        history = context.store.authority_resolver(peer.state.being_ref)
        assert isinstance(history, authority_epochs.RootHistoryAuthority)
        historical = history.select({"manifest_hash": old.authority.manifest.digest})
        self.assertEqual(historical.manifest, old.authority.manifest)
        self.assertEqual(historical.state, old.authority.state)
        self.assertEqual(
            historical.credentials[old.credential["artifact_id"]], old.credential
        )
        credential = next(
            c
            for c in peer_bundle["credentials"]
            if c["schema"] == "dm.identity.artifact/v2"
        )
        for field in ("control_artifacts", "incarnations"):
            with self.subTest(field=field):
                invalid = copy.deepcopy(bundle)
                invalid["sources"]["known_beings"][0][field] = [credential]
                self.assertFalse(validator.is_valid(invalid))
        for change in ({"unknown": True}, {"schema": "dm.identity.credential/v3"}):
            with self.subTest(change=change):
                invalid = copy.deepcopy(bundle)
                invalid["sources"]["known_beings"][0]["credentials"] = [
                    {**credential, **change}
                ]
                self.assertFalse(validator.is_valid(invalid))

    def test_v8_schema_accepts_actual_v2_known_peer(self):
        import json

        from jsonschema import Draft202012Validator

        from daimon_matrix.synthetic_relationships import _seed
        from tests.test_issue136_permissions import V2Journey

        root, bundle, _cap, _active = self.migrated_bundle()
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/hosted/v8/bundle.schema.json"
            ).read_text()
        )
        Draft202012Validator(schema).validate(bundle)  # local-only V8 positive control
        with tempfile.TemporaryDirectory(prefix="independent136-peer-") as tmp:
            journey = V2Journey(Path(tmp))
            peer = journey.identities["founder"].authority
            genesis = identity.create_synthetic_genesis_in_process(
                [_seed(f"founder:root:{i}") for i in range(3)],
                2,
                [_seed(f"founder:recovery:{i}") for i in range(3)],
                2,
                created_at_ms=0,
                nonce=_seed("founder:being"),
            )
            self.assertEqual(genesis["artifact_id"], peer.state.head)
            bundle["sources"] = {
                "cas_filename": "source-cas.sqlite",
                "known_beings": [
                    {
                        "authority_history": [],
                        "control_artifacts": [genesis],
                        "control_head": peer.state.head,
                        "credentials": list(peer.credentials.values()),
                        "incarnations": list(peer.incarnations.values()),
                        "ledger_filename": "peer-ledger.sqlite",
                        "manifest": peer.manifest.value,
                    }
                ],
            }
            bundle["relationships"] = {
                "known_being_refs": [peer.state.being_ref],
                "store_filename": "rels.sqlite",
            }
            (root / "runtime.json").write_bytes(canonical_bytes(bundle))
            loaded = runtime.load_runtime(
                root,
                "runtime.json",
                password_reader=lambda: bytearray(PASSWORD),
                clock=lambda: NOW + 10,
            )
            self.assertEqual(
                loaded.service.relationships.authority_resolver(peer.state.being_ref),
                peer,
            )
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas/hosted/v8/bundle.schema.json"
                ).read_text()
            )
            errors = list(Draft202012Validator(schema).iter_errors(bundle))

            def leaf_paths(error):
                if not error.context:
                    return [
                        "/".join(map(str, error.absolute_path)) + ": " + error.validator
                    ]
                return [path for child in error.context for path in leaf_paths(child)]

            self.assertEqual(
                len(errors),
                0,
                "runtime accepted V2 peer but published V8 schema rejects it: "
                + "; ".join(path for error in errors for path in leaf_paths(error)),
            )


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
