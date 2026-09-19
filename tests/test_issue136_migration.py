"""Signed same-embodiment succession and genuine hosted startup."""

import copy
import tempfile
from pathlib import Path

from daimon_matrix import (
    authority_epochs,
    identity,
    local_api,
    operator_rebirth,
    runtime,
)
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
    def messaging_migration(
        self,
        *,
        migration_id="12345678-1234-4234-8234-123456789136",
        output_generation=2,
    ):
        state_root, old_bundle, _cap = self.make_bundle()
        active, transition = successor(self)
        new_bundle = copy.deepcopy(old_bundle)
        new_bundle.update(
            schema="dm.runtime.bundle/v8",
            manifest=active.manifest.value,
            credentials=list(active.credentials.values()),
            incarnations=list(active.incarnations.values()),
            authority_history=[
                {"manifest": self.manifest.value, "successor": transition}
            ],
        )
        preserved = {
            "inbox": "messaging-inbox.sqlite",
            "outbox": "messaging-outbox.sqlite",
            "rpc": "messaging-rpc.sqlite",
        }
        for role, name in preserved.items():
            path = state_root / name
            path.write_bytes((role + "-original").encode())
            path.chmod(0o600)
        journal_key = b"issue136-migration-journal-key!!"
        heads = {
            "old_policy_head": "1" * 64,
            "new_policy_head": "2" * 64,
            "old_relationship_head": "3" * 64,
            "new_relationship_head": "4" * 64,
        }
        approval = operator_rebirth.create_messaging_permissions_migration_approval(
            old_bundle,
            new_bundle,
            state_root=state_root,
            migration_id=migration_id,
            output_generation=output_generation,
            capability_journal_identity="dm:capability-journal:v1:issue136",
            journal_key=journal_key,
            preserved_references=preserved,
            owner_signing_seed=self.signing_seeds["legion"],
            **heads,
        )
        return state_root, old_bundle, new_bundle, approval, journal_key, heads

    def assert_migration_not_committed(self, state_root, old_bundle):
        import json

        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(old_bundle)
        )
        self.assertFalse(
            (state_root / ".runtime.json.messaging-v2-generation.json").exists()
        )
        journal = json.loads(
            (state_root / ".runtime.json.messaging-v2-migration.json").read_bytes()
        )
        self.assertEqual(journal["state"], "prepared")

    def assert_final_publication_races_reject_before_install_and_retry(self, artifact):
        import json
        import os
        import shutil

        last_state_root = None
        for subject in ("runtime", "inbox", "outbox", "rpc"):
            for mode in ("mutation", "replacement"):
                with self.subTest(artifact=artifact, subject=subject, mode=mode):
                    if last_state_root is not None:
                        shutil.rmtree(last_state_root, ignore_errors=True)
                    (
                        state_root,
                        _old_bundle,
                        new_bundle,
                        approval,
                        journal_key,
                        heads,
                    ) = self.messaging_migration()
                    last_state_root = state_root
                    self.addCleanup(shutil.rmtree, state_root, ignore_errors=True)
                    operator_rebirth.prepare_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        new_bundle,
                        approval,
                        journal_key=journal_key,
                        current_policy_head=heads["old_policy_head"],
                        current_relationship_head=heads["old_relationship_head"],
                    )
                    journal_path = (
                        state_root / ".runtime.json.messaging-v2-migration.json"
                    )
                    floor_path = (
                        state_root / ".runtime.json.messaging-v2-generation.json"
                    )
                    target = state_root / (
                        "runtime.json"
                        if subject == "runtime"
                        else f"messaging-{subject}.sqlite"
                    )
                    approved = (
                        canonical_bytes(new_bundle)
                        if subject == "runtime"
                        else target.read_bytes()
                    )
                    prepared_bytes = journal_path.read_bytes()
                    raced = False

                    def race(
                        stage,
                        *,
                        bundle=new_bundle,
                        subject_name=subject,
                        change_mode=mode,
                        target_path=target,
                        root_path=state_root,
                    ):
                        nonlocal raced
                        if (
                            stage != f"{artifact}:after_file_fsync_before_install"
                            or raced
                        ):
                            return
                        raced = True
                        changed = (
                            canonical_bytes(
                                {**bundle, "runtime_label": "unapproved-runtime"}
                            )
                            if subject_name == "runtime"
                            else f"changed-before-{artifact}-install".encode()
                        )
                        if change_mode == "mutation":
                            target_path.write_bytes(changed)
                            target_path.chmod(0o600)
                        else:
                            replacement = root_path / f".attacker-{subject_name}"
                            replacement.write_bytes(changed)
                            replacement.chmod(0o600)
                            os.replace(replacement, target_path)

                    error = (
                        "messaging_migration_installed_runtime_rejected"
                        if subject == "runtime"
                        else "messaging_migration_preserved_reference_changed"
                    )
                    with self.assertRaisesRegex(operator_rebirth.RebirthError, error):
                        operator_rebirth.resume_messaging_permissions_migration(
                            state_root,
                            "runtime.json",
                            journal_key=journal_key,
                            current_policy_head=heads["old_policy_head"],
                            current_relationship_head=heads["old_relationship_head"],
                            fault_hook=race,
                        )
                    self.assertTrue(raced)
                    self.assertEqual(floor_path.exists(), artifact == "completion")
                    self.assertEqual(journal_path.read_bytes(), prepared_bytes)
                    self.assertEqual(json.loads(prepared_bytes)["state"], "prepared")

                    target.write_bytes(approved)
                    target.chmod(0o600)
                    result = operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["new_policy_head"],
                        current_relationship_head=heads["new_relationship_head"],
                    )
                    self.assertEqual(result["state"], "completed")
                    authoritative = (
                        state_root / "runtime.json",
                        floor_path,
                        journal_path,
                        state_root / "messaging-inbox.sqlite",
                        state_root / "messaging-outbox.sqlite",
                        state_root / "messaging-rpc.sqlite",
                    )
                    completed_bytes = tuple(path.read_bytes() for path in authoritative)
                    result = operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["new_policy_head"],
                        current_relationship_head=heads["new_relationship_head"],
                    )
                    self.assertEqual(result["state"], "completed")
                    self.assertEqual(
                        tuple(path.read_bytes() for path in authoritative),
                        completed_bytes,
                    )
                    self.assertFalse(
                        any(".staging" in path.name for path in state_root.iterdir())
                    )
                    shutil.rmtree(state_root)

    def test_floor_final_publication_races_reject_before_install_and_retry(self):
        self.assert_final_publication_races_reject_before_install_and_retry("floor")

    def test_completion_final_publication_races_reject_before_install_and_retry(self):
        self.assert_final_publication_races_reject_before_install_and_retry(
            "completion"
        )

    def test_precommit_substitution_mutation_and_root_swaps_reject_then_retry(self):
        import json
        import os
        import shutil

        # The checked candidate inode, not a later resolution of its name, is the
        # only object authorized for installation.
        state_root, old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def substitute_candidate(stage):
            if stage == "after_candidate_durable":
                candidate = state_root / ".runtime.json.messaging-v2-candidate"
                replacement = state_root / ".attacker-candidate"
                tampered = copy.deepcopy(new_bundle)
                tampered["runtime_label"] = "unapproved-substitute"
                replacement.write_bytes(canonical_bytes(tampered))
                replacement.chmod(0o600)
                os.replace(replacement, candidate)

        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_candidate_changed"
        ):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=substitute_candidate,
            )
        self.assert_migration_not_committed(state_root, old_bundle)
        result = operator_rebirth.resume_messaging_permissions_migration(
            state_root,
            "runtime.json",
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        self.assertEqual(result["state"], "completed")
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(new_bundle)
        )
        shutil.rmtree(state_root)

        # Each approved preserved role stays descriptor-bound through commit.
        for role in ("inbox", "outbox", "rpc"):
            with self.subTest(preserved_role=role):
                state_root, old_bundle, new_bundle, approval, journal_key, heads = (
                    self.messaging_migration()
                )
                operator_rebirth.prepare_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    new_bundle,
                    approval,
                    journal_key=journal_key,
                    current_policy_head=heads["old_policy_head"],
                    current_relationship_head=heads["old_relationship_head"],
                )
                path = state_root / f"messaging-{role}.sqlite"
                original = path.read_bytes()

                def mutate_reference(
                    stage,
                    *,
                    target=path,
                    root_path=state_root,
                    role_name=role,
                ):
                    if stage == "after_candidate_durable":
                        replacement = root_path / f".attacker-{role_name}"
                        replacement.write_bytes(b"changed-after-check")
                        replacement.chmod(0o600)
                        os.replace(replacement, target)

                with self.assertRaisesRegex(
                    operator_rebirth.RebirthError,
                    "messaging_migration_preserved_reference_changed",
                ):
                    operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["old_policy_head"],
                        current_relationship_head=heads["old_relationship_head"],
                        fault_hook=mutate_reference,
                    )
                self.assert_migration_not_committed(state_root, old_bundle)
                path.write_bytes(original)
                path.chmod(0o600)
                result = operator_rebirth.resume_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    journal_key=journal_key,
                    current_policy_head=heads["old_policy_head"],
                    current_relationship_head=heads["old_relationship_head"],
                )
                self.assertEqual(result["state"], "completed")
                shutil.rmtree(state_root)

        # Replacing the selected root through any pre-floor boundary is detected
        # against the retained directory descriptor.  Repairing the original
        # pathname permits the exact authenticated transaction to converge.
        for boundary in (
            "after_candidate_durable",
            "before_runtime_install",
            "before_generation_floor_install",
        ):
            with self.subTest(root_swap_boundary=boundary):
                state_root, old_bundle, new_bundle, approval, journal_key, heads = (
                    self.messaging_migration()
                )
                operator_rebirth.prepare_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    new_bundle,
                    approval,
                    journal_key=journal_key,
                    current_policy_head=heads["old_policy_head"],
                    current_relationship_head=heads["old_relationship_head"],
                )
                moved = state_root.with_name(state_root.name + "-moved")

                def swap_root(
                    stage,
                    *,
                    target_boundary=boundary,
                    root_path=state_root,
                    moved_path=moved,
                ):
                    if stage == target_boundary:
                        os.rename(root_path, moved_path)
                        root_path.mkdir(mode=0o700)

                with self.assertRaisesRegex(
                    operator_rebirth.RebirthError,
                    "messaging_migration_state_root_changed",
                ):
                    operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["old_policy_head"],
                        current_relationship_head=heads["old_relationship_head"],
                        fault_hook=swap_root,
                    )
                self.assertFalse(
                    (moved / ".runtime.json.messaging-v2-generation.json").exists()
                )
                self.assertEqual(
                    json.loads(
                        (
                            moved / ".runtime.json.messaging-v2-migration.json"
                        ).read_bytes()
                    )["state"],
                    "prepared",
                )
                state_root.rmdir()
                os.rename(moved, state_root)
                runtime_bytes = (state_root / "runtime.json").read_bytes()
                if runtime_bytes == canonical_bytes(old_bundle):
                    policy_head = heads["old_policy_head"]
                    relationship_head = heads["old_relationship_head"]
                else:
                    self.assertEqual(runtime_bytes, canonical_bytes(new_bundle))
                    policy_head = heads["new_policy_head"]
                    relationship_head = heads["new_relationship_head"]
                result = operator_rebirth.resume_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    journal_key=journal_key,
                    current_policy_head=policy_head,
                    current_relationship_head=relationship_head,
                )
                self.assertEqual(result["state"], "completed")
                shutil.rmtree(state_root)

    def test_ancestor_swaps_at_each_precommit_boundary_reject_then_retry(self):
        import json
        import os
        import shutil

        for boundary in (
            "after_candidate_durable",
            "before_runtime_install",
            "before_generation_floor_install",
        ):
            with self.subTest(ancestor_swap_boundary=boundary):
                state_root, old_bundle, new_bundle, approval, journal_key, heads = (
                    self.messaging_migration()
                )
                operator_rebirth.prepare_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    new_bundle,
                    approval,
                    journal_key=journal_key,
                    current_policy_head=heads["old_policy_head"],
                    current_relationship_head=heads["old_relationship_head"],
                )
                ancestor = state_root.parent
                moved_ancestor = ancestor.with_name(ancestor.name + "-moved")
                moved_root = moved_ancestor / state_root.name

                def swap_ancestor(
                    stage,
                    *,
                    target_boundary=boundary,
                    ancestor_path=ancestor,
                    moved_path=moved_ancestor,
                    root_path=state_root,
                ):
                    if stage == target_boundary:
                        os.rename(ancestor_path, moved_path)
                        ancestor_path.mkdir(mode=0o700)
                        root_path.mkdir(mode=0o700)

                with self.assertRaisesRegex(
                    operator_rebirth.RebirthError,
                    "messaging_migration_state_root_changed",
                ):
                    operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["old_policy_head"],
                        current_relationship_head=heads["old_relationship_head"],
                        fault_hook=swap_ancestor,
                    )
                self.assertFalse(
                    (moved_root / ".runtime.json.messaging-v2-generation.json").exists()
                )
                self.assertEqual(
                    json.loads(
                        (
                            moved_root / ".runtime.json.messaging-v2-migration.json"
                        ).read_bytes()
                    )["state"],
                    "prepared",
                )
                shutil.rmtree(ancestor)
                os.rename(moved_ancestor, ancestor)
                runtime_bytes = (state_root / "runtime.json").read_bytes()
                if runtime_bytes == canonical_bytes(old_bundle):
                    policy_head = heads["old_policy_head"]
                    relationship_head = heads["old_relationship_head"]
                else:
                    self.assertEqual(runtime_bytes, canonical_bytes(new_bundle))
                    policy_head = heads["new_policy_head"]
                    relationship_head = heads["new_relationship_head"]
                result = operator_rebirth.resume_messaging_permissions_migration(
                    state_root,
                    "runtime.json",
                    journal_key=journal_key,
                    current_policy_head=policy_head,
                    current_relationship_head=relationship_head,
                )
                self.assertEqual(result["state"], "completed")
                shutil.rmtree(state_root)

    def test_interrupted_atomic_publication_cleans_owned_residue_and_converges(self):
        import json
        import shutil

        artifacts = ("initial_journal", "candidate", "floor", "completion")
        boundaries = (
            "after_first_byte",
            "after_full_write_before_fsync",
            "after_file_fsync_before_install",
            "after_install_before_directory_fsync",
        )
        last_state_root = None
        for artifact in artifacts:
            for boundary in boundaries:
                with self.subTest(artifact=artifact, boundary=boundary):
                    if last_state_root is not None:
                        shutil.rmtree(last_state_root, ignore_errors=True)
                    state_root, old_bundle, new_bundle, approval, journal_key, heads = (
                        self.messaging_migration()
                    )
                    last_state_root = state_root
                    target = f"{artifact}:{boundary}"

                    def interrupt(stage, *, target_stage=target):
                        if stage == target_stage:
                            raise OSError(
                                5, f"synthetic interruption at {target_stage}"
                            )

                    if artifact != "initial_journal":
                        operator_rebirth.prepare_messaging_permissions_migration(
                            state_root,
                            "runtime.json",
                            new_bundle,
                            approval,
                            journal_key=journal_key,
                            current_policy_head=heads["old_policy_head"],
                            current_relationship_head=heads["old_relationship_head"],
                        )
                    with self.assertRaisesRegex(OSError, "synthetic interruption"):
                        if artifact == "initial_journal":
                            operator_rebirth.prepare_messaging_permissions_migration(
                                state_root,
                                "runtime.json",
                                new_bundle,
                                approval,
                                journal_key=journal_key,
                                current_policy_head=heads["old_policy_head"],
                                current_relationship_head=heads[
                                    "old_relationship_head"
                                ],
                                fault_hook=interrupt,
                            )
                        else:
                            operator_rebirth.resume_messaging_permissions_migration(
                                state_root,
                                "runtime.json",
                                journal_key=journal_key,
                                current_policy_head=heads["old_policy_head"],
                                current_relationship_head=heads[
                                    "old_relationship_head"
                                ],
                                fault_hook=interrupt,
                            )

                    runtime_raw = (state_root / "runtime.json").read_bytes()
                    self.assertIn(
                        runtime_raw,
                        {canonical_bytes(old_bundle), canonical_bytes(new_bundle)},
                    )
                    journal_path = (
                        state_root / ".runtime.json.messaging-v2-migration.json"
                    )
                    if journal_path.exists():
                        journal_raw = journal_path.read_bytes()
                        journal = json.loads(journal_raw)
                        self.assertEqual(canonical_bytes(journal), journal_raw)
                        self.assertIn(journal["state"], {"prepared", "completed"})
                    floor_path = (
                        state_root / ".runtime.json.messaging-v2-generation.json"
                    )
                    if floor_path.exists():
                        floor_raw = floor_path.read_bytes()
                        self.assertEqual(
                            canonical_bytes(json.loads(floor_raw)), floor_raw
                        )
                    candidate_path = state_root / ".runtime.json.messaging-v2-candidate"
                    if candidate_path.exists():
                        self.assertEqual(
                            candidate_path.read_bytes(), canonical_bytes(new_bundle)
                        )
                    if artifact in {"initial_journal", "candidate"}:
                        self.assertFalse(floor_path.exists())
                        if journal_path.exists():
                            self.assertEqual(
                                json.loads(journal_path.read_bytes())["state"],
                                "prepared",
                            )

                    if artifact == "initial_journal":
                        operator_rebirth.prepare_messaging_permissions_migration(
                            state_root,
                            "runtime.json",
                            new_bundle,
                            approval,
                            journal_key=journal_key,
                            current_policy_head=heads["old_policy_head"],
                            current_relationship_head=heads["old_relationship_head"],
                        )
                    if (state_root / "runtime.json").read_bytes() == canonical_bytes(
                        old_bundle
                    ):
                        policy_head = heads["old_policy_head"]
                        relationship_head = heads["old_relationship_head"]
                    else:
                        policy_head = heads["new_policy_head"]
                        relationship_head = heads["new_relationship_head"]
                    result = operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=policy_head,
                        current_relationship_head=relationship_head,
                    )
                    self.assertEqual(result["state"], "completed")
                    authoritative = (
                        state_root / "runtime.json",
                        floor_path,
                        journal_path,
                    )
                    final_bytes = tuple(path.read_bytes() for path in authoritative)
                    result = operator_rebirth.resume_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        journal_key=journal_key,
                        current_policy_head=heads["new_policy_head"],
                        current_relationship_head=heads["new_relationship_head"],
                    )
                    self.assertEqual(result["state"], "completed")
                    self.assertEqual(
                        tuple(path.read_bytes() for path in authoritative), final_bytes
                    )
                    self.assertFalse(
                        any(".staging" in path.name for path in state_root.iterdir())
                    )
                    shutil.rmtree(state_root)

    def test_sensitive_migration_files_reject_hardlinks_promptly(self):
        import os
        import shutil

        last_state_root = None

        def fresh():
            nonlocal last_state_root
            if last_state_root is not None:
                shutil.rmtree(last_state_root, ignore_errors=True)
            fixture = self.messaging_migration()
            last_state_root = fixture[0]
            return fixture

        # CLI journal-key custody uses the same pre/post-open single-link rule.
        state_root, _old, _new, _approval, journal_key, _heads = fresh()
        key_path = state_root / "migration.key"
        key_path.write_bytes(journal_key)
        key_path.chmod(0o600)
        os.link(key_path, state_root / "migration-key-alias")
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_journal_key_rejected"
        ):
            operator_rebirth._messaging_migration_journal_key(key_path)

        for role in ("runtime", "inbox", "outbox", "rpc"):
            with self.subTest(role=role):
                state_root, _old, new_bundle, approval, journal_key, heads = fresh()
                name = (
                    "runtime.json" if role == "runtime" else f"messaging-{role}.sqlite"
                )
                os.link(state_root / name, state_root / f"{name}.alias")
                with self.assertRaises(operator_rebirth.RebirthError):
                    operator_rebirth.prepare_messaging_permissions_migration(
                        state_root,
                        "runtime.json",
                        new_bundle,
                        approval,
                        journal_key=journal_key,
                        current_policy_head=heads["old_policy_head"],
                        current_relationship_head=heads["old_relationship_head"],
                    )

        state_root, _old, new_bundle, approval, journal_key, heads = fresh()
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        journal_path = state_root / ".runtime.json.messaging-v2-migration.json"
        os.link(journal_path, state_root / ".journal-alias")
        with self.assertRaises(operator_rebirth.RebirthError):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

        state_root, _old, new_bundle, approval, journal_key, heads = fresh()
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def stop_at_candidate(stage):
            if stage == "after_candidate_durable":
                raise RuntimeError("candidate retained")

        with self.assertRaisesRegex(RuntimeError, "candidate retained"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=stop_at_candidate,
            )
        candidate_path = state_root / ".runtime.json.messaging-v2-candidate"
        os.link(candidate_path, state_root / ".candidate-alias")
        with self.assertRaises(operator_rebirth.RebirthError):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

        state_root, _old, new_bundle, approval, journal_key, heads = fresh()
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def stop_at_floor(stage):
            if stage == "after_generation_floor_durable":
                raise RuntimeError("floor retained")

        with self.assertRaisesRegex(RuntimeError, "floor retained"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=stop_at_floor,
            )
        floor_path = state_root / ".runtime.json.messaging-v2-generation.json"
        os.link(floor_path, state_root / ".floor-alias")
        with self.assertRaises(operator_rebirth.RebirthError):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["new_policy_head"],
                current_relationship_head=heads["new_relationship_head"],
            )

    def test_prepare_journal_is_authenticated_exact_and_restartable_after_fault(self):
        import json

        state_root, old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )

        def crash(stage):
            if stage == "after_journal_durable":
                raise RuntimeError("synthetic journal crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic journal crash"):
            operator_rebirth.prepare_messaging_permissions_migration(
                state_root,
                "runtime.json",
                new_bundle,
                approval,
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=crash,
            )
        journal_path = state_root / ".runtime.json.messaging-v2-migration.json"
        journal_before = journal_path.read_bytes()
        journal = json.loads(journal_before)
        self.assertEqual(journal["state"], "prepared")
        self.assertEqual(journal["approval"], approval)
        self.assertEqual(
            journal["approval"]["body"]["old"]["bundle_sha256"],
            __import__("hashlib").sha256(canonical_bytes(old_bundle)).hexdigest(),
        )
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(old_bundle)
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        self.assertEqual(journal_path.read_bytes(), journal_before)
        tampered = json.loads(journal_before)
        tampered["state"] = "completed"
        journal_path.write_bytes(canonical_bytes(tampered))
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError,
            "messaging_migration_journal_authentication_failed",
        ):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

    def test_candidate_durable_fault_resumes_without_touching_old_state(self):
        state_root, old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        preserved_before = {
            name: (state_root / name).read_bytes()
            for name in (
                "messaging-inbox.sqlite",
                "messaging-outbox.sqlite",
                "messaging-rpc.sqlite",
            )
        }

        def crash(stage):
            if stage == "after_candidate_durable":
                raise RuntimeError("synthetic candidate crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic candidate crash"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=crash,
            )
        candidate = state_root / ".runtime.json.messaging-v2-candidate"
        self.assertEqual(candidate.read_bytes(), canonical_bytes(new_bundle))
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(old_bundle)
        )
        operator_rebirth.resume_messaging_permissions_migration(
            state_root,
            "runtime.json",
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(new_bundle)
        )
        self.assertEqual(
            {name: (state_root / name).read_bytes() for name in preserved_before},
            preserved_before,
        )

    def test_output_durable_fault_restarts_from_new_heads_and_converges(self):
        import json

        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def crash(stage):
            if stage == "after_output_durable":
                raise RuntimeError("synthetic output crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic output crash"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=crash,
            )
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(new_bundle)
        )
        journal_path = state_root / ".runtime.json.messaging-v2-migration.json"
        self.assertEqual(json.loads(journal_path.read_bytes())["state"], "prepared")
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_head_conflict"
        ):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )
        result = operator_rebirth.resume_messaging_permissions_migration(
            state_root,
            "runtime.json",
            journal_key=journal_key,
            current_policy_head=heads["new_policy_head"],
            current_relationship_head=heads["new_relationship_head"],
        )
        self.assertEqual(result["state"], "completed")
        loaded = runtime.load_runtime(
            state_root,
            "runtime.json",
            password_reader=lambda: bytearray(PASSWORD),
            clock=lambda: NOW + 10,
        )
        self.assertEqual(
            loaded.service.ledger.authority.manifest.digest,
            authority_from_runtime_bundle(new_bundle).manifest.digest,
        )

    def test_generation_floor_durable_fault_is_authenticated_and_resumable(self):
        import json

        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def crash(stage):
            if stage == "after_generation_floor_durable":
                raise RuntimeError("synthetic floor crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic floor crash"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=crash,
            )
        floor_path = state_root / ".runtime.json.messaging-v2-generation.json"
        floor_before = floor_path.read_bytes()
        floor = json.loads(floor_before)
        self.assertEqual(floor["generation"], 2)
        self.assertEqual(
            floor["output_bundle_sha256"], approval["body"]["new"]["bundle_sha256"]
        )
        self.assertEqual(
            floor["capability_journal"], approval["body"]["capability_journal"]
        )
        result = operator_rebirth.resume_messaging_permissions_migration(
            state_root,
            "runtime.json",
            journal_key=journal_key,
            current_policy_head=heads["new_policy_head"],
            current_relationship_head=heads["new_relationship_head"],
        )
        self.assertEqual(result["state"], "completed")
        self.assertEqual(floor_path.read_bytes(), floor_before)

    def test_completion_durable_fault_exact_retry_converges(self):
        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )

        def crash(stage):
            if stage == "after_completion_durable":
                raise RuntimeError("synthetic completion crash")

        with self.assertRaisesRegex(RuntimeError, "synthetic completion crash"):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
                fault_hook=crash,
            )
        paths = (
            state_root / "runtime.json",
            state_root / ".runtime.json.messaging-v2-generation.json",
            state_root / ".runtime.json.messaging-v2-migration.json",
        )
        completed_bytes = tuple(path.read_bytes() for path in paths)
        for _ in range(2):
            result = operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["new_policy_head"],
                current_relationship_head=heads["new_relationship_head"],
            )
            self.assertEqual(result["state"], "completed")
            self.assertEqual(
                tuple(path.read_bytes() for path in paths), completed_bytes
            )

    def test_operator_cli_apply_and_resume_execute_the_transaction(self):
        import io
        from unittest import mock

        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        candidate_path = state_root / "messaging-v2-candidate.json"
        approval_path = state_root / "messaging-v2-approval.json"
        key_path = state_root / "messaging-v2-journal.key"
        for path, content in (
            (candidate_path, canonical_bytes(new_bundle)),
            (approval_path, canonical_bytes(approval)),
            (key_path, journal_key),
        ):
            path.write_bytes(content)
            path.chmod(0o600)

        class Capture:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, value):
                return len(value)

            def flush(self):
                return None

        capture = Capture()
        with mock.patch.object(operator_rebirth.sys, "stdout", capture):
            result = operator_rebirth.main(
                [
                    "apply-messaging-permissions-migration",
                    "--state-root",
                    str(state_root),
                    "--runtime-name",
                    "runtime.json",
                    "--candidate",
                    str(candidate_path),
                    "--approval",
                    str(approval_path),
                    "--journal-key-file",
                    str(key_path),
                    "--current-policy-head",
                    heads["old_policy_head"],
                    "--current-relationship-head",
                    heads["old_relationship_head"],
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(
            (state_root / "runtime.json").read_bytes(), canonical_bytes(new_bundle)
        )
        capture = Capture()
        with mock.patch.object(operator_rebirth.sys, "stdout", capture):
            result = operator_rebirth.main(
                [
                    "resume-messaging-permissions-migration",
                    "--state-root",
                    str(state_root),
                    "--runtime-name",
                    "runtime.json",
                    "--journal-key-file",
                    str(key_path),
                    "--current-policy-head",
                    heads["new_policy_head"],
                    "--current-relationship-head",
                    heads["new_relationship_head"],
                ]
            )
        self.assertEqual(result, 0)

    def test_stale_generation_conflicting_journal_and_runtime_are_rejected(self):
        state_root, old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration(output_generation=3)
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        operator_rebirth.resume_messaging_permissions_migration(
            state_root,
            "runtime.json",
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        (state_root / "runtime.json").write_bytes(canonical_bytes(old_bundle))
        preserved = {
            "inbox": "messaging-inbox.sqlite",
            "outbox": "messaging-outbox.sqlite",
            "rpc": "messaging-rpc.sqlite",
        }
        stale = operator_rebirth.create_messaging_permissions_migration_approval(
            old_bundle,
            new_bundle,
            state_root=state_root,
            migration_id="12345678-1234-4234-8234-123456789137",
            output_generation=2,
            capability_journal_identity="dm:capability-journal:v1:issue136",
            journal_key=journal_key,
            preserved_references=preserved,
            owner_signing_seed=self.signing_seeds["legion"],
            **heads,
        )
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_stale_generation"
        ):
            operator_rebirth.prepare_messaging_permissions_migration(
                state_root,
                "runtime.json",
                new_bundle,
                stale,
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )
        conflicting = operator_rebirth.create_messaging_permissions_migration_approval(
            old_bundle,
            new_bundle,
            state_root=state_root,
            migration_id="12345678-1234-4234-8234-123456789138",
            output_generation=3,
            capability_journal_identity="dm:capability-journal:v1:issue136",
            journal_key=journal_key,
            preserved_references=preserved,
            owner_signing_seed=self.signing_seeds["legion"],
            **heads,
        )
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_generation_conflict"
        ):
            operator_rebirth.prepare_messaging_permissions_migration(
                state_root,
                "runtime.json",
                new_bundle,
                conflicting,
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )
        (state_root / ".runtime.json.messaging-v2-generation.json").unlink()
        (state_root / ".runtime.json.messaging-v2-migration.json").unlink()
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            stale,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        tampered_runtime = copy.deepcopy(old_bundle)
        tampered_runtime["runtime_label"] = "conflicting-runtime"
        (state_root / "runtime.json").write_bytes(canonical_bytes(tampered_runtime))
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "messaging_migration_runtime_conflict"
        ):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

    def test_preserved_inbox_outbox_rpc_reference_change_stops_resume(self):
        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        operator_rebirth.prepare_messaging_permissions_migration(
            state_root,
            "runtime.json",
            new_bundle,
            approval,
            journal_key=journal_key,
            current_policy_head=heads["old_policy_head"],
            current_relationship_head=heads["old_relationship_head"],
        )
        (state_root / "messaging-rpc.sqlite").write_bytes(b"changed")
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError,
            "messaging_migration_preserved_reference_changed",
        ):
            operator_rebirth.resume_messaging_permissions_migration(
                state_root,
                "runtime.json",
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

    def test_owner_approval_binds_exact_capability_journal_key_identity(self):
        state_root, _old_bundle, new_bundle, approval, journal_key, heads = (
            self.messaging_migration()
        )
        malformed = copy.deepcopy(approval)
        malformed["body"]["capability_journal"].pop("key_id")
        malformed["signature"] = operator_rebirth._request_signature(
            self.signing_seeds["legion"],
            malformed["body"],
            domain=operator_rebirth.MESSAGING_MIGRATION_APPROVAL_DOMAIN,
        )
        with self.assertRaisesRegex(
            operator_rebirth.RebirthError, "invalid_messaging_migration_approval"
        ):
            operator_rebirth.prepare_messaging_permissions_migration(
                state_root,
                "runtime.json",
                new_bundle,
                malformed,
                journal_key=journal_key,
                current_policy_head=heads["old_policy_head"],
                current_relationship_head=heads["old_relationship_head"],
            )

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
