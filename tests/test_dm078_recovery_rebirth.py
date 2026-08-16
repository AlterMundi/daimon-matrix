from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest import mock

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

from daimon_matrix.authority_epochs import (
    AuthorityEpochError,
    RootHistoryAuthority,
    create_recovery_rebirth,
    verify_recovery_rebirth,
)
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import CLIENT_CONFIG_SCHEMA_V3
from daimon_matrix.identity import (
    create_embodiment_credential,
    create_incarnation_authorization,
    create_revocation,
    create_synthetic_recovery_in_process,
    ed25519_public,
    key_descriptor,
    signing_descriptor,
    verify_genesis,
    verify_recovery,
    verify_successor,
    x25519_public,
)
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.ledger import Ledger
from daimon_matrix.operator_capabilities import (
    OBSERVE_PROFILE,
    OPERATOR_PROFILE_NAMES,
    create_operator_capability_binding,
    create_operator_capability_set,
    operator_capability_profile,
    operator_runtime_id,
)
from daimon_matrix.operator_genesis import PENDING_CONTROL_HEAD
from daimon_matrix.operator_rebirth import (
    RebirthError,
    activate_recovery_target_runtime,
    aggregate_distributed_recovery,
    aggregate_distributed_recovery_authorization,
    authority_from_runtime_bundle,
    authorize_enrollment_request,
    authorize_synthetic_recovery_enrollment_in_process,
    authorize_synthetic_single_store_recovery,
    create_distributed_recovery_authorization_intent,
    create_distributed_recovery_authorization_share,
    create_distributed_recovery_intent,
    create_distributed_recovery_share,
    create_enrollment_request,
    create_recovery_target_preparation,
    create_replacement_root_holder,
    create_synthetic_single_store_recovery_custody,
    recovery_request_base,
    restore_recovery_ledger,
    validate_activation,
    validate_enrollment_request,
    validate_recovery_activation,
)
from daimon_matrix.operator_rebirth import (
    parser as rebirth_parser,
)
from daimon_matrix.runtime import RuntimeError as HostedRuntimeError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import BeingManifest, EventSigner, RootAuthority
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed
from tools.generate_dm078_recovery_vectors import generate as generate_vectors


def _test_password_reader(value: bytes) -> Callable[[], bytearray]:
    return lambda: bytearray(value)


class TestRecoveryRebirthAuthority(RootLedgerFixture):
    def test_documented_rebirth_commands_are_current_public_surface(self) -> None:
        documentation = (
            Path(__file__).resolve().parents[1] / "docs/dm078-fresh-host-rebirth.md"
        ).read_text(encoding="utf-8")
        documented = set(
            re.findall(
                r"^(?:daimon-rebirth|python -m daimon_matrix\.operator_rebirth) "
                r"([a-z-]+)\s*\\?$",
                documentation,
                flags=re.MULTILINE,
            )
        )
        expected = {
            "activate",
            "activate-recovery",
            "aggregate-recovery",
            "aggregate-recovery-authorization",
            "authorize",
            "create-recovery-authorization-intent",
            "create-recovery-intent",
            "create-replacement-root-holder",
            "prepare",
            "prepare-recovery",
            "recovery-authorization-share",
            "recovery-share",
        }
        assert documented == expected
        assert not any(command.startswith("synthetic-") for command in documented)
        subparsers = next(
            action
            for action in rebirth_parser()._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        assert documented <= set(subparsers.choices)

    def _authority_document(self) -> dict[str, Any]:
        return {
            "schema": "dm.operator.authority/v1",
            "control_artifacts": [self.genesis],
            "control_head": self.state.head,
            "manifest": self.manifest.value,
            "credentials": list(self.credentials.values()),
            "incarnations": list(self.incarnations.values()),
        }

    def _base_runtime_bundle(self) -> dict[str, Any]:
        runtime_id = operator_runtime_id(
            "legion",
            self.state.being_ref,
            self.origins["legion"],
            signing_descriptor(self.signing_seeds["legion"])["key_id"],
        )
        return {
            "schema": "dm.runtime.bundle/v7",
            "operator_capability_binding": None,
            "runtime_id": runtime_id,
            "runtime_label": "legion",
            "control_artifacts": [self.genesis],
            "control_head": self.state.head,
            "manifest": self.manifest.value,
            "authority_history": [],
            "credentials": list(self.credentials.values()),
            "incarnations": list(self.incarnations.values()),
            "binding": None,
            "binding_activation": None,
            "provisional_history": None,
            "local_origin": self.origins["legion"],
            "ledger": "ledger.sqlite",
            "socket": "matrix.sock",
            "keystore": {
                "filename": "custody.json",
                "counter": 1,
                "signing_slot": "runtime.signing.v1:legion",
            },
            "capabilities": [],
            "routing": None,
            "scopes": {"body_capabilities": [], "relationships_filename": None},
            "peer_transport": {
                "enabled": True,
                "encryption_slot": "peer.encryption.v1:legion",
                "exchange_filename": "peer-exchange.sqlite",
                "listen_host": "127.0.0.1",
                "listen_port": 8686,
                "outbox_filename": "peer-outbox.sqlite",
                "targets": [
                    {
                        "embodiment_id": self.origins["daimonmatrix"]["embodiment_id"],
                        "endpoint": "http://127.0.0.1:18686/dm-peer/v1",
                        "timeout_ms": 5_000,
                    }
                ],
            },
            "species": None,
            "sources": {"cas_filename": "sources.sqlite3", "known_beings": []},
            "relationships": {
                "known_being_refs": [],
                "store_filename": "relationships.sqlite3",
            },
        }

    def _invoke_rebirth_cli(
        self,
        arguments: list[str],
        passwords: dict[str, bytes] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        descriptors: dict[str, int] = {}
        readers: list[int] = []
        for marker, password in (passwords or {}).items():
            reader, writer = os.pipe()
            os.write(writer, password)
            os.close(writer)
            descriptors[marker] = reader
            readers.append(reader)
        try:
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.operator_rebirth",
                    *[
                        str(descriptors[value]) if value in descriptors else value
                        for value in arguments
                    ],
                ],
                cwd=Path(__file__).resolve().parents[1],
                env={
                    **os.environ,
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                },
                pass_fds=tuple(descriptors.values()),
                capture_output=True,
                check=False,
            )
        finally:
            for descriptor in readers:
                os.close(descriptor)

    def _successor(
        self,
        *,
        revoked: list[str] | None = None,
        previous: RootAuthority | None = None,
        embodiment_id: str = "embodiment:recovered-target",
        replacement_roots: list[bytes] | None = None,
    ) -> tuple[RootAuthority, dict[str, Any], dict[str, Any], dict[str, str], bytes]:
        previous = self.authority if previous is None else previous
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = (
            [
                seed("replacement-root-a"),
                seed("replacement-root-b"),
                seed("replacement-root-c"),
            ]
            if replacement_roots is None
            else replacement_roots
        )
        active = sorted(
            row["embodiment_id"]
            for row in previous.manifest.value["embodiments"]
            if row["status"] == "active"
        )
        recovery = create_synthetic_recovery_in_process(
            [previous.state],
            recovery_seeds,
            replacement_roots,
            2,
            revoke_embodiments=active if revoked is None else revoked,
        )
        recovered = verify_recovery(recovery, [previous.state])
        signing_seed = seed("recovered-target-signing")
        transport_seed = seed("recovered-target-transport")
        credential = create_embodiment_credential(
            recovered,
            replacement_roots[:2],
            signing_seed,
            x25519_public(seed("recovered-target-encryption")),
            embodiment_id=embodiment_id,
            body_ref="cluster:recovery-target:compaii",
            purposes=["dm.we", "messages"],
            valid_from_ms=NOW + 10,
            valid_until_ms=NOW + 100_000,
            transport_principals=[
                {
                    "scheme": "dm-peer-v1",
                    "principal_id": "compaii@recovery-target",
                    "key": key_descriptor("Ed25519", ed25519_public(transport_seed)),
                }
            ],
        )
        incarnation = create_incarnation_authorization(
            credential,
            signing_seed,
            incarnation_id="incarnation:recovered-target:0",
            incarnation_sequence=0,
            started_at_ms=NOW + 10,
        )
        origin = {
            "body_ref": "cluster:recovery-target:compaii",
            "embodiment_id": embodiment_id,
            "incarnation_id": "incarnation:recovered-target:0",
            "principal_id": "compaii@recovery-target",
        }
        manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": previous.state.being_ref,
                "control_head": recovered.head,
                "history_binding_id": previous.manifest.value["history_binding_id"],
                "revision": previous.manifest.value["revision"] + 1,
                "embodiments": [
                    {
                        "body_ref": origin["body_ref"],
                        "embodiment_credential_id": credential["artifact_id"],
                        "embodiment_id": origin["embodiment_id"],
                        "incarnation_authorization_id": incarnation["artifact_id"],
                        "incarnation_id": origin["incarnation_id"],
                        "status": "active",
                    }
                ],
            }
        )
        successor = RootAuthority(
            manifest,
            recovered,
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
        transition = create_recovery_rebirth(
            previous.manifest,
            manifest,
            recovery_artifact=recovery,
            body_ref=origin["body_ref"],
            embodiment_id=origin["embodiment_id"],
            incarnation_id=origin["incarnation_id"],
            embodiment_credential_id=credential["artifact_id"],
            incarnation_authorization_id=incarnation["artifact_id"],
            principal_id=origin["principal_id"],
            root_seeds=replacement_roots[:2],
            issued_at_ms=NOW + 20,
        )
        return successor, transition, recovery, origin, signing_seed

    def test_recovery_quorum_bridges_old_history_to_only_fresh_body(self) -> None:
        old_event = self.append(self.ledger_a, "legion", "before-recovery")
        successor, transition, recovery, origin, signing_seed = self._successor()
        assert (
            verify_recovery_rebirth(transition, self.authority, successor, recovery)
            == transition
        )
        history = RootHistoryAuthority(successor, [self.authority], [transition])
        assert set(transition["revoked_embodiment_ids"]) == {
            self.origins["legion"]["embodiment_id"],
            self.origins["daimonmatrix"]["embodiment_id"],
        }
        assert history.active.manifest.value["embodiments"] == [
            successor.manifest.value["embodiments"][0]
        ]

        fresh = Ledger(
            Path(self.root_path) / "recovered" / "ledger.sqlite",
            authority=history,
            local_origin=origin,
            clock=lambda: NOW + 30,
        )
        fresh.initialize()
        assert (
            fresh.ingest(self.ledger_a.delta([]), source="restored-backup")["missing"]
            == 1
        )
        assert fresh.event(old_event["event_id"]) == old_event
        appended = fresh.append_local(
            kind="experience.observed",
            subject="post-recovery",
            payload={"summary": "post-recovery"},
            signer=EventSigner(
                signing_descriptor(signing_seed)["key_id"], signing_seed
            ),
            occurred_at_ms=NOW + 30,
        )
        assert appended["origin"] == origin
        assert appended["manifest_hash"] == successor.manifest.digest
        with self.assertRaisesRegex(AuthorityEpochError, "unknown_manifest_hash"):
            history.select({"manifest_hash": "0" * 64})

    def test_recovery_and_ordinary_enrollment_compose_in_both_orders(self) -> None:
        recovered, recovery_transition, recovery, _origin, _seed = self._successor()
        request = create_enrollment_request(
            recovered,
            signing_seed=seed("post-recovery-peer-signing"),
            encryption_private=seed("post-recovery-peer-encryption"),
            transport_seed=seed("post-recovery-peer-transport"),
            body_ref="cluster:post-recovery:peer",
            embodiment_id="embodiment:post-recovery:peer",
            incarnation_id="incarnation:post-recovery:peer:0",
            principal_id="compaii@post-recovery-peer",
            created_at_ms=NOW + 30,
            expires_at_ms=NOW + 60_030,
            nonce=seed("post-recovery-peer-nonce"),
        )
        activation = authorize_enrollment_request(
            request,
            recovered,
            root_seeds=[
                seed("replacement-root-a"),
                seed("replacement-root-b"),
            ],
            issued_at_ms=NOW + 40,
        )
        _verified, active, _history = validate_activation(
            activation, recovered, request=request
        )
        history = RootHistoryAuthority(
            active,
            [self.authority, recovered],
            [recovery_transition, activation["body"]["transition"]],
        )
        assert set(history.accepted_manifest_hashes) == {
            self.manifest.digest,
            recovered.manifest.digest,
            active.manifest.digest,
        }

        bundle = self._base_runtime_bundle()
        bundle["control_artifacts"] = [self.genesis, recovery]
        bundle["control_head"] = recovery["artifact_id"]
        bundle["manifest"] = active.manifest.value
        bundle["credentials"] = list(active.credentials.values())
        bundle["incarnations"] = list(active.incarnations.values())
        bundle["authority_history"] = [
            {
                "manifest": self.manifest.value,
                "control_artifacts": [self.genesis],
                "control_head": self.state.head,
                "credentials": list(self.credentials.values()),
                "incarnations": list(self.incarnations.values()),
                "successor": recovery_transition,
            },
            {
                "manifest": recovered.manifest.value,
                "successor": activation["body"]["transition"],
            },
        ]
        loaded = authority_from_runtime_bundle(bundle)
        assert loaded.manifest.digest == active.manifest.digest

        ordinary_request = create_enrollment_request(
            self.authority,
            signing_seed=seed("pre-recovery-peer-signing"),
            encryption_private=seed("pre-recovery-peer-encryption"),
            transport_seed=seed("pre-recovery-peer-transport"),
            body_ref="cluster:pre-recovery:peer",
            embodiment_id="embodiment:pre-recovery:peer",
            incarnation_id="incarnation:pre-recovery:peer:0",
            principal_id="compaii@pre-recovery-peer",
            created_at_ms=NOW + 30,
            expires_at_ms=NOW + 60_030,
            nonce=seed("pre-recovery-peer-nonce"),
        )
        ordinary_activation = authorize_enrollment_request(
            ordinary_request,
            self.authority,
            root_seeds=self.root_seeds[:2],
            issued_at_ms=NOW + 40,
        )
        _verified, enrolled, _history = validate_activation(
            ordinary_activation,
            self.authority,
            request=ordinary_request,
        )
        recovered_again, second_transition, second_recovery, origin, signing_seed = (
            self._successor(previous=enrolled)
        )
        reverse_bundle = self._base_runtime_bundle()
        reverse_bundle["control_artifacts"] = [self.genesis, second_recovery]
        reverse_bundle["control_head"] = second_recovery["artifact_id"]
        reverse_bundle["manifest"] = recovered_again.manifest.value
        reverse_bundle["credentials"] = list(recovered_again.credentials.values())
        reverse_bundle["incarnations"] = list(recovered_again.incarnations.values())
        reverse_bundle["authority_history"] = [
            {
                "manifest": self.manifest.value,
                "successor": ordinary_activation["body"]["transition"],
            },
            {
                "manifest": enrolled.manifest.value,
                "control_artifacts": [self.genesis],
                "control_head": self.state.head,
                "credentials": list(enrolled.credentials.values()),
                "incarnations": list(enrolled.incarnations.values()),
                "successor": second_transition,
            },
        ]
        reverse_bundle["local_origin"] = origin
        reverse_bundle["peer_transport"]["targets"] = []
        loaded_reverse = authority_from_runtime_bundle(reverse_bundle)
        assert loaded_reverse.manifest.digest == recovered_again.manifest.digest

        runtime_root = self.root_path / "ordinary-then-recovery-runtime"
        runtime_root.mkdir(mode=0o700)
        runtime_password = b"ordinary-then-recovery-password"
        operator_capabilities, operator_keys, operator_slots = (
            create_operator_capability_set("ordinary-then-recovery", issued_at_ms=NOW)
        )
        runtime_label = "ordinary-then-recovery"
        runtime_id = operator_runtime_id(
            runtime_label,
            recovered_again.state.being_ref,
            origin,
            signing_descriptor(signing_seed)["key_id"],
        )
        reverse_bundle["runtime_id"] = runtime_id
        reverse_bundle["runtime_label"] = runtime_label
        reverse_bundle["keystore"]["signing_slot"] = (
            "runtime.signing.v1:ordinary-then-recovery"
        )
        reverse_bundle["peer_transport"]["encryption_slot"] = (
            "peer.encryption.v1:ordinary-then-recovery"
        )
        reverse_bundle["capabilities"] = [
            {
                "descriptor": operator_capabilities[profile].descriptor,
                "profile": operator_capability_profile(profile),
                "runtime_id": runtime_id,
                "secret_slot": operator_slots[profile],
            }
            for profile in OPERATOR_PROFILE_NAMES
        ]
        reverse_bundle["operator_capability_binding"] = (
            create_operator_capability_binding(
                runtime_id=runtime_id,
                runtime_label=runtime_label,
                being_ref=recovered_again.state.being_ref,
                origin=origin,
                signing_seed=signing_seed,
                capability_rows=reverse_bundle["capabilities"],
            )
        )
        EncryptedKeystore.create(
            runtime_root / "custody.json",
            lambda: bytearray(runtime_password),
            control_head=second_recovery["artifact_id"],
            secrets={
                "runtime.signing.v1:ordinary-then-recovery": signing_seed,
                "peer.encryption.v1:ordinary-then-recovery": seed(
                    "recovered-target-encryption"
                ),
                **{
                    operator_slots[profile]: operator_keys[profile]
                    for profile in OPERATOR_PROFILE_NAMES
                },
            },
        )
        (runtime_root / "client.json").write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA_V3,
                    "capability": operator_capabilities[OBSERVE_PROFILE].descriptor,
                    "expected_server": origin,
                    "runtime_id": runtime_id,
                    "runtime_label": runtime_label,
                }
            )
        )
        (runtime_root / "client.json").chmod(0o600)
        (runtime_root / "client.key").write_bytes(operator_keys[OBSERVE_PROFILE])
        (runtime_root / "client.key").chmod(0o600)
        operator_clients = runtime_root / "operator-clients"
        operator_clients.mkdir(mode=0o700)
        for profile in OPERATOR_PROFILE_NAMES:
            if profile == OBSERVE_PROFILE:
                continue
            role_root = operator_clients / profile
            role_root.mkdir(mode=0o700)
            (role_root / "client.json").write_bytes(
                canonical_bytes(
                    {
                        "schema": CLIENT_CONFIG_SCHEMA_V3,
                        "capability": operator_capabilities[profile].descriptor,
                        "expected_server": origin,
                        "runtime_id": runtime_id,
                        "runtime_label": runtime_label,
                    }
                )
            )
            (role_root / "client.json").chmod(0o600)
            (role_root / "capability.key").write_bytes(operator_keys[profile])
            (role_root / "capability.key").chmod(0o600)
        runtime_path = runtime_root / "runtime.json"
        runtime_path.write_bytes(canonical_bytes(reverse_bundle))
        runtime_path.chmod(0o600)
        hosted = load_runtime(
            runtime_root,
            "runtime.json",
            lambda: bytearray(runtime_password),
            clock=lambda: NOW + 50,
        )
        assert isinstance(hosted.service.ledger.authority, RootHistoryAuthority)
        assert set(hosted.service.ledger.authority.accepted_manifest_hashes) == {
            self.manifest.digest,
            enrolled.manifest.digest,
            recovered_again.manifest.digest,
        }

    def test_recovery_must_revoke_every_predecessor_and_bind_exact_bytes(self) -> None:
        successor, transition, recovery, _origin, _signing_seed = self._successor()
        incomplete = self._successor(revoked=[self.origins["legion"]["embodiment_id"]])[
            1
        ]
        with self.assertRaisesRegex(AuthorityEpochError, "lineage_mismatch"):
            verify_recovery_rebirth(incomplete, self.authority, successor)

        tampered = copy.deepcopy(transition)
        tampered["principal_id"] = "compaii@forged"
        with self.assertRaises(AuthorityEpochError):
            verify_recovery_rebirth(tampered, self.authority, successor, recovery)

        wrong_signature = copy.deepcopy(transition)
        wrong_signature["signatures"][0]["value"] = "A" * 86
        with self.assertRaisesRegex(AuthorityEpochError, "signature_invalid"):
            verify_recovery_rebirth(
                wrong_signature, self.authority, successor, recovery
            )

        reused_root_successor, reused_root_transition, reused_root_recovery, *_ = (
            self._successor(replacement_roots=list(self.root_seeds))
        )
        with self.assertRaisesRegex(AuthorityEpochError, "lineage_mismatch"):
            verify_recovery_rebirth(
                reused_root_transition,
                self.authority,
                reused_root_successor,
            )
        with self.assertRaisesRegex(RebirthError, "root_reuse"):
            recovery_request_base(self.authority, reused_root_recovery)

        retired_manifest_value = copy.deepcopy(self.manifest.value)
        retired_manifest_value["embodiments"][0]["status"] = "retired"
        retired_previous = RootAuthority(
            BeingManifest.from_value(retired_manifest_value),
            self.state,
            self.credentials,
            self.incarnations,
        )
        retired_id = retired_manifest_value["embodiments"][0]["embodiment_id"]
        reused_successor, reused_transition, *_ = self._successor(
            previous=retired_previous,
            embodiment_id=retired_id,
        )
        with self.assertRaisesRegex(AuthorityEpochError, "manifest_change_forbidden"):
            verify_recovery_rebirth(
                reused_transition, retired_previous, reused_successor
            )

    def test_recovery_transition_matches_closed_public_schema(self) -> None:
        _successor, transition, _recovery, _origin, _seed = self._successor()
        root = Path(__file__).resolve().parents[1]
        identity_schema = json.loads(
            (root / "schemas/identity/v1/artifact.schema.json").read_bytes()
        )
        transition_schema = json.loads(
            (root / "schemas/weave/v1/recovery-rebirth.schema.json").read_bytes()
        )
        registry = Registry().with_resource(
            identity_schema["$id"], Resource.from_contents(identity_schema)
        )
        Draft202012Validator(transition_schema, registry=registry).validate(transition)
        Draft202012Validator.check_schema(transition_schema)

    def test_public_recovery_vectors_verify_and_regenerate_byte_identically(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        vector_root = root / "vectors/weave/v1/recovery-rebirth"
        index = json.loads((vector_root / "index.json").read_bytes())
        previous = BeingManifest.from_value(
            json.loads((vector_root / index["previous_manifest"]).read_bytes())
        )
        identity = index["identity"]
        state = verify_genesis(
            json.loads((vector_root / identity["genesis"]).read_bytes())
        )
        credential = json.loads(
            (vector_root / identity["existing_embodiment_credential"]).read_bytes()
        )
        incarnation = json.loads(
            (vector_root / identity["existing_incarnation_authorization"]).read_bytes()
        )
        base = RootAuthority(
            previous,
            state,
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
        recovery = json.loads((vector_root / index["recovery_artifact"]).read_bytes())
        request_base = recovery_request_base(base, recovery)
        request = json.loads((vector_root / index["request"]).read_bytes())
        validate_enrollment_request(request, request_base, observed_at_ms=NOW + 20)
        activation = json.loads((vector_root / index["activation"]).read_bytes())
        _verified, successor, _history = validate_recovery_activation(
            activation, base, request=request
        )

        bad_recovery = json.loads(
            (vector_root / index["negative_recovery"]).read_bytes()
        )
        with self.assertRaisesRegex(RebirthError, "artifact_invalid"):
            recovery_request_base(base, bad_recovery)
        bad_transition = json.loads(
            (vector_root / index["negative_transition"]).read_bytes()
        )
        with self.assertRaisesRegex(AuthorityEpochError, "hash_mismatch"):
            verify_recovery_rebirth(bad_transition, base, successor)

        with TemporaryDirectory(prefix="dm078-recovery-vectors-") as directory:
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
            assert actual == expected

    def test_target_request_is_signed_only_after_verified_recovery(self) -> None:
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = [
            seed("replacement-root-a"),
            seed("replacement-root-b"),
            seed("replacement-root-c"),
        ]
        active = sorted(
            row["embodiment_id"]
            for row in self.manifest.value["embodiments"]
            if row["status"] == "active"
        )
        recovery = create_synthetic_recovery_in_process(
            [self.state],
            recovery_seeds,
            replacement_roots,
            2,
            revoke_embodiments=active,
        )
        request_base = recovery_request_base(self.authority, recovery)
        target_signing = seed("recovered-request-signing")
        request = create_enrollment_request(
            request_base,
            signing_seed=target_signing,
            encryption_private=seed("recovered-request-encryption"),
            transport_seed=seed("recovered-request-transport"),
            body_ref="cluster:recovery-target:compaii",
            embodiment_id="embodiment:recovered-request-target",
            incarnation_id="incarnation:recovered-request-target:0",
            principal_id="compaii@recovered-request-target",
            created_at_ms=NOW + 10,
            expires_at_ms=NOW + 60_010,
            nonce=seed("recovered-request-nonce"),
        )
        assert request["body"]["control_head"] == request_base.state.head
        assert request["body"]["base_manifest_hash"] == self.manifest.digest
        activation = authorize_synthetic_recovery_enrollment_in_process(
            request,
            self.authority,
            recovery,
            replacement_root_seeds=replacement_roots[:2],
            issued_at_ms=NOW + 20,
        )
        verified, successor, history = validate_recovery_activation(
            activation, self.authority, request=request
        )
        assert verified == activation
        assert successor.state.head == recovery["artifact_id"]
        assert history.historical == [self.authority]
        assert successor.manifest.value["embodiments"][0]["embodiment_id"] == (
            "embodiment:recovered-request-target"
        )

        incomplete = create_synthetic_recovery_in_process(
            [self.state],
            recovery_seeds,
            replacement_roots,
            2,
            revoke_embodiments=active[:1],
        )
        with self.assertRaisesRegex(RebirthError, "incomplete_revocation"):
            recovery_request_base(self.authority, incomplete)
        changed = copy.deepcopy(activation)
        changed["body"]["recovered_control_head"] = self.state.head
        with self.assertRaisesRegex(RebirthError, "base_mismatch"):
            validate_recovery_activation(changed, self.authority, request=request)

    def test_recovery_preparation_builds_loadable_target_only_runtime(self) -> None:
        old_event = self.append(self.ledger_a, "legion", "before-runtime-recovery")
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = [
            seed("replacement-runtime-root-a"),
            seed("replacement-runtime-root-b"),
            seed("replacement-runtime-root-c"),
        ]
        active = sorted(
            row["embodiment_id"]
            for row in self.manifest.value["embodiments"]
            if row["status"] == "active"
        )
        recovery = create_synthetic_recovery_in_process(
            [self.state],
            recovery_seeds,
            replacement_roots,
            2,
            revoke_embodiments=active,
        )
        ceremony = self.root_path / "recovery-runtime"
        ceremony.mkdir(mode=0o700)
        target_password = b"recovery-target-runtime-password"
        preparation = create_recovery_target_preparation(
            ceremony / "preparation",
            self.authority,
            recovery,
            {
                "schema": "dm.operator.rebirth-target-profile/v1",
                "label": "recovered",
                "body_ref": "cluster:recovered:compaii",
                "principal_id": "compaii@recovered",
                "listen_host": "127.0.0.1",
                "listen_port": 28687,
                "advertised_endpoint": "http://127.0.0.1:28687/dm-peer/v1",
                "targets": [],
            },
            lambda: bytearray(target_password),
            created_at_ms=NOW + 10,
            expires_at_ms=NOW + 60_010,
        )
        request = json.loads((ceremony / "preparation/request.json").read_bytes())
        activation = authorize_synthetic_recovery_enrollment_in_process(
            request,
            self.authority,
            recovery,
            replacement_root_seeds=replacement_roots[:2],
            issued_at_ms=NOW + 20,
        )
        receipt = activate_recovery_target_runtime(
            ceremony / "package",
            ceremony / "preparation",
            preparation,
            request,
            activation,
            self._base_runtime_bundle(),
            lambda: bytearray(target_password),
        )
        runtime_root = ceremony / "package/runtime"
        snapshot_root = self.root_path / "legion"
        snapshot_bundle = snapshot_root / "runtime.json"
        snapshot_bundle.write_bytes(canonical_bytes(self._base_runtime_bundle()))
        snapshot_bundle.chmod(0o600)
        source_evidence = {
            "bundle_sha256": hashlib.sha256(
                (snapshot_root / "runtime.json").read_bytes()
            ).hexdigest(),
            "bundle_size": (snapshot_root / "runtime.json").stat().st_size,
            "ledger_sha256": hashlib.sha256(
                (snapshot_root / "ledger.sqlite").read_bytes()
            ).hexdigest(),
            "ledger_size": (snapshot_root / "ledger.sqlite").stat().st_size,
        }
        protected_before = {
            name: hashlib.sha256((runtime_root / name).read_bytes()).hexdigest()
            for name in ("runtime.json", "custody.json", "transport-custody.json")
        }
        restore_receipt = restore_recovery_ledger(
            runtime_root,
            snapshot_root,
            lambda: bytearray(target_password),
            source_evidence=source_evidence,
            clock=lambda: NOW + 30,
        )
        hosted = load_runtime(
            runtime_root,
            "runtime.json",
            lambda: bytearray(target_password),
            clock=lambda: NOW + 30,
        )
        assert hosted.service.ledger.events() == [old_event]
        assert receipt["empty_writable_state"] is True
        assert restore_receipt["event_count"] == 1
        assert restore_receipt["inserted_count"] == 1
        assert protected_before == {
            name: hashlib.sha256((runtime_root / name).read_bytes()).hexdigest()
            for name in ("runtime.json", "custody.json", "transport-custody.json")
        }
        assert restore_recovery_ledger(
            runtime_root,
            snapshot_root,
            lambda: bytearray(target_password),
            source_evidence=source_evidence,
            clock=lambda: NOW + 30,
        ) == {**restore_receipt, "inserted_count": 0}
        with self.assertRaisesRegex(RebirthError, "source_evidence_mismatch"):
            restore_recovery_ledger(
                runtime_root,
                snapshot_root,
                lambda: bytearray(target_password),
                source_evidence={**source_evidence, "ledger_sha256": "0" * 64},
                clock=lambda: NOW + 30,
            )
        outside = self.root_path / "outside-ledger.sqlite"
        outside.write_bytes(b"must-not-be-read")
        outside.chmod(0o600)
        source_ledger = snapshot_root / "ledger.sqlite"
        original_ledger = snapshot_root / "ledger-original.sqlite"
        real_open = os.open
        swapped = False

        def swap_before_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            nonlocal swapped
            if Path(path) == source_ledger:
                swapped = True
                source_ledger.rename(original_ledger)
                source_ledger.symlink_to(outside)
            return real_open(path, flags, *args, **kwargs)

        with (
            mock.patch(
                "daimon_matrix.operator_rebirth.os.open", side_effect=swap_before_open
            ),
            self.assertRaisesRegex(RebirthError, "snapshot_ledger_rejected"),
        ):
            restore_recovery_ledger(
                runtime_root,
                snapshot_root,
                lambda: bytearray(target_password),
                source_evidence=source_evidence,
                clock=lambda: NOW + 30,
            )
        assert swapped is True
        assert hosted.service.ledger.events() == [old_event]
        assert isinstance(hosted.service.ledger.authority, RootHistoryAuthority)
        assert set(hosted.service.ledger.authority.accepted_manifest_hashes) == {
            self.manifest.digest,
            receipt["successor_manifest_hash"],
        }
        assert hosted.service.ledger.event(old_event["event_id"]) == old_event
        bundle = json.loads((runtime_root / "runtime.json").read_bytes())
        assert bundle["control_head"] == recovery["artifact_id"]
        assert bundle["peer_transport"]["targets"] == []
        assert len(bundle["manifest"]["embodiments"]) == 1
        assert len(bundle["authority_history"]) == 1
        hosted_schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/hosted/v7/bundle.schema.json"
            ).read_bytes()
        )
        Draft202012Validator(hosted_schema).validate(bundle)
        Draft202012Validator.check_schema(hosted_schema)

        # A recovered authority can also be represented as a known source.  The
        # duplicate being is rejected only after its enriched history verifies.
        duplicate_source = {
            key: copy.deepcopy(bundle[key])
            for key in (
                "authority_history",
                "control_artifacts",
                "control_head",
                "credentials",
                "incarnations",
                "manifest",
            )
        }
        duplicate_source["ledger_filename"] = "known-recovered.sqlite"
        bundle["sources"]["known_beings"] = [duplicate_source]
        (runtime_root / "runtime.json").write_bytes(canonical_bytes(bundle))
        with self.assertRaisesRegex(
            HostedRuntimeError, "runtime_source_being_conflict"
        ):
            load_runtime(
                runtime_root,
                "runtime.json",
                lambda: bytearray(target_password),
                clock=lambda: NOW + 30,
            )

    def test_offline_recovery_custody_drops_old_roots_and_authorizes_target(
        self,
    ) -> None:
        ceremony = self.root_path / "offline-recovery"
        ceremony.mkdir(mode=0o700)
        old_password = b"offline-old-recovery-password"
        new_password = b"offline-new-recovery-password"
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        old_store = ceremony / "old-root-custody.json"
        EncryptedKeystore.create(
            old_store,
            lambda: bytearray(old_password),
            control_head=self.state.head,
            secrets={
                **{
                    f"root.signing.v1:{index}": value
                    for index, value in enumerate(self.root_seeds)
                },
                **{
                    f"recovery.signing.v1:{index}": value
                    for index, value in enumerate(recovery_seeds)
                },
            },
        )
        receipt = create_synthetic_single_store_recovery_custody(
            ceremony / "successor",
            self.authority,
            old_store,
            lambda: bytearray(old_password),
            lambda: bytearray(new_password),
        )
        recovery = json.loads((ceremony / "successor/recovery.json").read_bytes())
        new_contents = EncryptedKeystore(ceremony / "successor/root-custody.json").open(
            lambda: bytearray(new_password),
            required_control_head=recovery["artifact_id"],
        )
        assert receipt["old_root_material_retained"] is False
        assert not set(self.root_seeds) & set(new_contents.secrets.values())
        assert set(recovery_seeds) <= set(new_contents.secrets.values())

        custody_secrets = {
            **{
                f"root.signing.v1:{index}": value
                for index, value in enumerate(self.root_seeds)
            },
            **{
                f"recovery.signing.v1:{index}": value
                for index, value in enumerate(recovery_seeds)
            },
        }
        wrong_store = ceremony / "wrong-recovery-custody.json"
        EncryptedKeystore.create(
            wrong_store,
            lambda: bytearray(old_password),
            control_head=self.state.head,
            secrets={
                **custody_secrets,
                "recovery.signing.v1:0": seed("unauthorized-recovery"),
            },
        )
        with self.assertRaisesRegex(RebirthError, "custody_rejected"):
            create_synthetic_single_store_recovery_custody(
                ceremony / "wrong-successor",
                self.authority,
                wrong_store,
                lambda: bytearray(old_password),
                lambda: bytearray(new_password),
            )
        extra_store = ceremony / "extra-role-custody.json"
        EncryptedKeystore.create(
            extra_store,
            lambda: bytearray(old_password),
            control_head=self.state.head,
            secrets={
                **custody_secrets,
                "runtime.signing.v1:forbidden": seed("forbidden-runtime"),
            },
        )
        with self.assertRaisesRegex(RebirthError, "custody_rejected"):
            create_synthetic_single_store_recovery_custody(
                ceremony / "extra-successor",
                self.authority,
                extra_store,
                lambda: bytearray(old_password),
                lambda: bytearray(new_password),
            )

        request_base = recovery_request_base(self.authority, recovery)
        request = create_enrollment_request(
            request_base,
            signing_seed=seed("custody-target-signing"),
            encryption_private=seed("custody-target-encryption"),
            transport_seed=seed("custody-target-transport"),
            body_ref="cluster:custody-target:compaii",
            embodiment_id="embodiment:custody-target",
            incarnation_id="incarnation:custody-target:0",
            principal_id="compaii@custody-target",
            created_at_ms=NOW + 10,
            expires_at_ms=NOW + 60_010,
            nonce=seed("custody-target-nonce"),
        )
        activation = authorize_synthetic_single_store_recovery(
            request,
            self.authority,
            recovery,
            ceremony / "successor/root-custody.json",
            lambda: bytearray(new_password),
            issued_at_ms=NOW + 20,
        )
        validate_recovery_activation(activation, self.authority, request=request)
        extra_recovered_store = ceremony / "successor/extra-root-custody.json"
        EncryptedKeystore.create(
            extra_recovered_store,
            lambda: bytearray(new_password),
            control_head=recovery["artifact_id"],
            secrets={
                **new_contents.secrets,
                "runtime.signing.v1:forbidden": seed("forbidden-recovered-role"),
            },
        )
        with self.assertRaisesRegex(RebirthError, "custody_rejected"):
            authorize_synthetic_single_store_recovery(
                request,
                self.authority,
                recovery,
                extra_recovered_store,
                lambda: bytearray(new_password),
                issued_at_ms=NOW + 20,
            )
        public = json.dumps(
            {"receipt": receipt, "recovery": recovery, "activation": activation}
        )
        assert old_password.decode() not in public
        assert new_password.decode() not in public

    def test_distributed_recovery_aggregates_disjoint_holder_shares(self) -> None:
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = [
            seed("distributed-root-a"),
            seed("distributed-root-b"),
            seed("distributed-root-c"),
        ]
        intent = create_distributed_recovery_intent(
            self.authority,
            [signing_descriptor(value) for value in replacement_roots],
            2,
            created_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            nonce=seed("distributed-recovery-intent"),
        )
        shares = [
            create_distributed_recovery_share(
                intent,
                self.authority,
                value,
                observed_at_ms=NOW + 1,
            )
            for value in (
                recovery_seeds[0],
                replacement_roots[0],
                recovery_seeds[1],
                replacement_roots[1],
            )
        ]
        recovery = aggregate_distributed_recovery(
            intent,
            self.authority,
            shares,
            observed_at_ms=NOW + 2,
        )
        recovered = recovery_request_base(self.authority, recovery)
        self.assertEqual(recovered.state.head, recovery["artifact_id"])
        self.assertEqual(
            {row["key_id"] for row in recovered.state.root_policy["keys"]},
            {signing_descriptor(value)["key_id"] for value in replacement_roots},
        )
        public_exchange = canonical_bytes(
            {"intent": intent, "shares": shares, "recovery": recovery}
        )
        for private_seed in recovery_seeds + replacement_roots:
            self.assertNotIn(private_seed, public_exchange)

    def test_distributed_recovery_rejects_replay_substitution_and_shortfall(
        self,
    ) -> None:
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = [
            seed("distributed-hostile-root-a"),
            seed("distributed-hostile-root-b"),
            seed("distributed-hostile-root-c"),
        ]
        intent = create_distributed_recovery_intent(
            self.authority,
            [signing_descriptor(value) for value in replacement_roots],
            2,
            created_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            nonce=seed("distributed-hostile-intent"),
        )
        recovery_share = create_distributed_recovery_share(
            intent,
            self.authority,
            recovery_seeds[0],
            observed_at_ms=NOW + 1,
        )
        root_share = create_distributed_recovery_share(
            intent,
            self.authority,
            replacement_roots[0],
            observed_at_ms=NOW + 1,
        )
        with self.assertRaisesRegex(RebirthError, "threshold_rejected"):
            aggregate_distributed_recovery(
                intent,
                self.authority,
                [recovery_share, root_share],
                observed_at_ms=NOW + 2,
            )
        with self.assertRaisesRegex(RebirthError, "threshold_rejected"):
            aggregate_distributed_recovery(
                intent,
                self.authority,
                [recovery_share, recovery_share, root_share, root_share],
                observed_at_ms=NOW + 2,
            )
        substituted = copy.deepcopy(root_share)
        substituted["intent_id"] = "dm:recovery-intent:v1:substituted"
        with self.assertRaisesRegex(RebirthError, "invalid_rebirth_recovery_share"):
            aggregate_distributed_recovery(
                intent,
                self.authority,
                [recovery_share, substituted],
                observed_at_ms=NOW + 2,
            )
        second_intent = create_distributed_recovery_intent(
            self.authority,
            [signing_descriptor(value) for value in replacement_roots],
            2,
            created_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            nonce=seed("distributed-hostile-second-intent"),
        )
        transplanted = copy.deepcopy(recovery_share)
        transplanted["intent_id"] = second_intent["intent_id"]
        with self.assertRaisesRegex(RebirthError, "invalid_rebirth_recovery_share"):
            aggregate_distributed_recovery(
                second_intent,
                self.authority,
                [transplanted],
                observed_at_ms=NOW + 2,
            )
        with self.assertRaisesRegex(RebirthError, "holder_not_authorized"):
            create_distributed_recovery_share(
                intent,
                self.authority,
                seed("hostile-holder"),
                observed_at_ms=NOW + 1,
            )
        with self.assertRaisesRegex(RebirthError, "not_timely"):
            create_distributed_recovery_share(
                intent,
                self.authority,
                recovery_seeds[0],
                observed_at_ms=NOW + 60_000,
            )

    def test_distributed_root_holders_authorize_target_without_seed_aggregation(
        self,
    ) -> None:
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        replacement_roots = [
            seed("distributed-authorization-root-a"),
            seed("distributed-authorization-root-b"),
            seed("distributed-authorization-root-c"),
        ]
        recovery_intent = create_distributed_recovery_intent(
            self.authority,
            [signing_descriptor(value) for value in replacement_roots],
            2,
            created_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            nonce=seed("distributed-authorization-recovery-intent"),
        )
        recovery_shares = [
            create_distributed_recovery_share(
                recovery_intent,
                self.authority,
                value,
                observed_at_ms=NOW + 1,
            )
            for value in (
                recovery_seeds[0],
                recovery_seeds[1],
                replacement_roots[0],
                replacement_roots[1],
            )
        ]
        recovery = aggregate_distributed_recovery(
            recovery_intent,
            self.authority,
            recovery_shares,
            observed_at_ms=NOW + 2,
        )
        request = create_enrollment_request(
            recovery_request_base(self.authority, recovery),
            signing_seed=seed("distributed-target-signing"),
            encryption_private=seed("distributed-target-encryption"),
            transport_seed=seed("distributed-target-transport"),
            body_ref="cluster:distributed-target:compaii",
            embodiment_id="embodiment:distributed-target",
            incarnation_id="incarnation:distributed-target:0",
            principal_id="compaii@distributed-target",
            created_at_ms=NOW + 10,
            expires_at_ms=NOW + 60_010,
            nonce=seed("distributed-target-request"),
        )
        authorization_intent = create_distributed_recovery_authorization_intent(
            request,
            self.authority,
            recovery,
            issued_at_ms=NOW + 20,
            expires_at_ms=NOW + 60_020,
            nonce=seed("distributed-authorization-intent"),
        )
        authorization_shares = [
            create_distributed_recovery_authorization_share(
                authorization_intent,
                request,
                self.authority,
                recovery,
                value,
                observed_at_ms=NOW + 21,
            )
            for value in replacement_roots[:2]
        ]
        activation = aggregate_distributed_recovery_authorization(
            authorization_intent,
            request,
            self.authority,
            recovery,
            authorization_shares,
            observed_at_ms=NOW + 22,
        )
        validate_recovery_activation(activation, self.authority, request=request)
        public_exchange = canonical_bytes(
            {
                "recovery_intent": recovery_intent,
                "recovery_shares": recovery_shares,
                "recovery": recovery,
                "authorization_intent": authorization_intent,
                "authorization_shares": authorization_shares,
                "activation": activation,
            }
        )
        for private_seed in recovery_seeds + replacement_roots:
            self.assertNotIn(private_seed, public_exchange)
        with self.assertRaisesRegex(RebirthError, "threshold_rejected"):
            aggregate_distributed_recovery_authorization(
                authorization_intent,
                request,
                self.authority,
                recovery,
                authorization_shares[:1],
                observed_at_ms=NOW + 22,
            )

    def test_multi_head_recovery_runs_through_cli_and_authority_epoch(self) -> None:
        branch_artifacts = [
            create_revocation(
                self.state,
                self.root_seeds,
                embodiment_id=f"embodiment:retired-{index}",
                cutoff_incarnation_sequence=index,
                revocation_generation=1,
            )
            for index in (1, 2)
        ]
        branch_states = [
            verify_successor(artifact, self.state) for artifact in branch_artifacts
        ]
        branch_authorities: list[RootAuthority] = []
        branch_documents: list[dict[str, Any]] = []
        for branch_index, (artifact, state) in enumerate(
            zip(branch_artifacts, branch_states, strict=True)
        ):
            rows = copy.deepcopy(self.manifest.value["embodiments"])
            if branch_index == 0:
                rows[0]["status"] = "retired"
            manifest = BeingManifest.from_value(
                {
                    **self.manifest.value,
                    "control_head": state.head,
                    "embodiments": rows,
                }
            )
            authority = RootAuthority(
                manifest, state, self.credentials, self.incarnations
            )
            branch_authorities.append(authority)
            branch_documents.append(
                {
                    "schema": "dm.operator.authority/v1",
                    "control_artifacts": [self.genesis, artifact],
                    "control_head": state.head,
                    "manifest": manifest.value,
                    "credentials": list(self.credentials.values()),
                    "incarnations": list(self.incarnations.values()),
                }
            )

        root = self.root_path / "multi-head-cli"
        root.mkdir(mode=0o700)
        authority_paths: list[Path] = []
        for index, document in enumerate(branch_documents):
            path = root / f"branch-{index}.json"
            path.write_bytes(canonical_bytes(document))
            path.chmod(0o600)
            authority_paths.append(path)
        replacement_roots = [
            seed("multi-head-root-a"),
            seed("multi-head-root-b"),
            seed("multi-head-root-c"),
        ]
        descriptors: list[Path] = []
        for index, replacement_seed in enumerate(replacement_roots):
            package = root / f"replacement-{index}"
            create_replacement_root_holder(
                package,
                branch_authorities[0],
                _test_password_reader(f"multi-head-password-{index}".encode()),
            )
            # Bind the CLI intent to deterministic test keys so direct holder
            # shares below can prove the same exact multi-head artifact.
            descriptor = json.loads((package / "descriptor.json").read_bytes())
            descriptor["key"] = signing_descriptor(replacement_seed)
            path = root / f"descriptor-{index}.json"
            path.write_bytes(canonical_bytes(descriptor))
            path.chmod(0o600)
            descriptors.append(path)
        intent_path = root / "intent.json"
        result = self._invoke_rebirth_cli(
            [
                "create-recovery-intent",
                "--authority",
                str(authority_paths[0]),
                "--known-authority",
                str(authority_paths[1]),
                *(
                    item
                    for path in descriptors
                    for item in ("--holder-descriptor", str(path))
                ),
                "--threshold",
                "2",
                "--output",
                str(intent_path),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        intent = json.loads(intent_path.read_bytes())
        self.assertEqual(
            intent["body"]["known_control_heads"],
            sorted(state.head for state in branch_states),
        )
        self.assertEqual(
            intent["body"]["prepared_recovery"]["body"]["revoked_embodiments"],
            sorted(row["embodiment_id"] for row in self.manifest.value["embodiments"]),
        )
        recovery_seeds = [seed("recovery-a"), seed("recovery-b")]
        shares = [
            create_distributed_recovery_share(
                intent,
                branch_authorities[0],
                value,
                observed_at_ms=intent["body"]["created_at_ms"],
                known_states=branch_states,
                known_manifests=[
                    authority.manifest for authority in branch_authorities
                ],
            )
            for value in [*recovery_seeds, *replacement_roots[:2]]
        ]
        recovery = aggregate_distributed_recovery(
            intent,
            branch_authorities[0],
            shares,
            observed_at_ms=intent["body"]["created_at_ms"],
            known_states=branch_states,
            known_manifests=[authority.manifest for authority in branch_authorities],
        )
        request_base = recovery_request_base(branch_authorities[0], recovery)
        self.assertEqual(request_base.state.generation, 1)
        self.assertIn("embodiment:retired-2", request_base.state.revocations)
        signing_seed = seed("multi-head-target-signing")
        transport_seed = seed("multi-head-target-transport")
        credential = create_embodiment_credential(
            request_base.state,
            replacement_roots[:2],
            signing_seed,
            x25519_public(seed("multi-head-target-encryption")),
            embodiment_id="embodiment:multi-head-target",
            body_ref="cluster:multi-head-target:compaii",
            purposes=["dm.we", "messages"],
            valid_from_ms=NOW,
            valid_until_ms=NOW + 100_000,
            transport_principals=[
                {
                    "scheme": "dm-peer-v1",
                    "principal_id": "compaii@multi-head-target",
                    "key": key_descriptor("Ed25519", ed25519_public(transport_seed)),
                }
            ],
        )
        incarnation = create_incarnation_authorization(
            credential,
            signing_seed,
            incarnation_id="incarnation:multi-head-target:0",
            incarnation_sequence=0,
            started_at_ms=NOW,
        )
        manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": self.state.being_ref,
                "control_head": request_base.state.head,
                "history_binding_id": self.manifest.value["history_binding_id"],
                "revision": self.manifest.value["revision"] + 1,
                "embodiments": [
                    {
                        "body_ref": "cluster:multi-head-target:compaii",
                        "embodiment_credential_id": credential["artifact_id"],
                        "embodiment_id": "embodiment:multi-head-target",
                        "incarnation_authorization_id": incarnation["artifact_id"],
                        "incarnation_id": "incarnation:multi-head-target:0",
                        "status": "active",
                    }
                ],
            }
        )
        successor = RootAuthority(
            manifest,
            request_base.state,
            {credential["artifact_id"]: credential},
            {incarnation["artifact_id"]: incarnation},
        )
        transition = create_recovery_rebirth(
            branch_authorities[0].manifest,
            successor.manifest,
            recovery_artifact=recovery,
            body_ref="cluster:multi-head-target:compaii",
            embodiment_id="embodiment:multi-head-target",
            incarnation_id="incarnation:multi-head-target:0",
            embodiment_credential_id=credential["artifact_id"],
            incarnation_authorization_id=incarnation["artifact_id"],
            principal_id="compaii@multi-head-target",
            root_seeds=replacement_roots[:2],
            issued_at_ms=NOW + 1,
        )
        verify_recovery_rebirth(transition, branch_authorities[0], successor, recovery)
        RootHistoryAuthority(successor, [branch_authorities[0]], [transition])

    def test_distributed_custody_cli_isolates_every_holder_and_keyless_aggregator(
        self,
    ) -> None:
        root = self.root_path / "distributed-custody-cli"
        root.mkdir(mode=0o700)
        authority_path = root / "authority.json"
        authority_path.write_bytes(canonical_bytes(self._authority_document()))
        authority_path.chmod(0o600)
        recovery_passwords = [
            f"distributed-recovery-holder-{index}".encode() for index in range(3)
        ]
        recovery_holders: list[Path] = []
        recovery_seeds = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        for index, (password, recovery_seed) in enumerate(
            zip(recovery_passwords, recovery_seeds, strict=True)
        ):
            path = root / f"recovery-holder-{index}"
            path.mkdir(mode=0o700)
            EncryptedKeystore.create(
                path / "holder.json",
                _test_password_reader(password),
                control_head=PENDING_CONTROL_HEAD,
                secrets={"genesis.recovery.v1:holder": recovery_seed},
            )
            descriptor = path / "descriptor.json"
            descriptor.write_bytes(
                canonical_bytes(
                    {
                        "schema": "dm.operator.genesis-holder/v1",
                        "role": "recovery",
                        "key": signing_descriptor(recovery_seed),
                    }
                )
            )
            descriptor.chmod(0o600)
            recovery_holders.append(path)

        root_passwords = [
            f"distributed-root-holder-{index}".encode() for index in range(3)
        ]
        root_holders: list[Path] = []
        descriptors: list[Path] = []
        for index, password in enumerate(root_passwords):
            holder = root / f"root-holder-{index}"
            descriptor = holder / "descriptor.json"
            result = self._invoke_rebirth_cli(
                [
                    "create-replacement-root-holder",
                    "--authority",
                    str(authority_path),
                    "--password-fd",
                    "{password}",
                    "--output",
                    str(holder),
                ],
                {"{password}": password},
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            root_holders.append(holder)
            descriptors.append(descriptor)

        intent_path = root / "recovery-intent.json"
        arguments = [
            "create-recovery-intent",
            "--authority",
            str(authority_path),
            "--threshold",
            "2",
            "--output",
            str(intent_path),
        ]
        for descriptor in descriptors:
            arguments.extend(["--holder-descriptor", str(descriptor)])
        result = self._invoke_rebirth_cli(arguments)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

        recovery_share_paths: list[Path] = []
        for role, holders, passwords in (
            ("recovery", recovery_holders[:2], recovery_passwords[:2]),
            ("root", root_holders[:2], root_passwords[:2]),
        ):
            for index, (holder, password) in enumerate(
                zip(holders, passwords, strict=True)
            ):
                share_path = root / f"{role}-share-{index}.json"
                result = self._invoke_rebirth_cli(
                    [
                        "recovery-share",
                        "--authority",
                        str(authority_path),
                        "--intent",
                        str(intent_path),
                        "--holder",
                        str(holder),
                        "--password-fd",
                        "{password}",
                        "--output",
                        str(share_path),
                    ],
                    {"{password}": password},
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                recovery_share_paths.append(share_path)

        recovery_path = root / "recovery.json"
        arguments = [
            "aggregate-recovery",
            "--authority",
            str(authority_path),
            "--intent",
            str(intent_path),
            "--output",
            str(recovery_path),
        ]
        for share_path in recovery_share_paths:
            arguments.extend(["--share", str(share_path)])
        result = self._invoke_rebirth_cli(arguments)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        retry = self._invoke_rebirth_cli(arguments)
        self.assertEqual(retry.returncode, 0, retry.stderr.decode())
        recovery = json.loads(recovery_path.read_bytes())
        request_base = recovery_request_base(self.authority, recovery)
        wall_ms = time.time_ns() // 1_000_000
        request = create_enrollment_request(
            request_base,
            signing_seed=seed("distributed-cli-target-signing"),
            encryption_private=seed("distributed-cli-target-encryption"),
            transport_seed=seed("distributed-cli-target-transport"),
            body_ref="cluster:distributed-cli-target:compaii",
            embodiment_id="embodiment:distributed-cli-target",
            incarnation_id="incarnation:distributed-cli-target:0",
            principal_id="compaii@distributed-cli-target",
            created_at_ms=wall_ms - 1_000,
            expires_at_ms=wall_ms + 600_000,
            nonce=seed("distributed-cli-target-request"),
        )
        request_path = root / "request.json"
        request_path.write_bytes(canonical_bytes(request))
        request_path.chmod(0o600)
        authorization_intent_path = root / "authorization-intent.json"
        result = self._invoke_rebirth_cli(
            [
                "create-recovery-authorization-intent",
                "--authority",
                str(authority_path),
                "--recovery",
                str(recovery_path),
                "--request",
                str(request_path),
                "--output",
                str(authorization_intent_path),
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

        authorization_share_paths: list[Path] = []
        for index, (holder, password) in enumerate(
            zip(root_holders[:2], root_passwords[:2], strict=True)
        ):
            share_path = root / f"authorization-share-{index}.json"
            result = self._invoke_rebirth_cli(
                [
                    "recovery-authorization-share",
                    "--authority",
                    str(authority_path),
                    "--recovery",
                    str(recovery_path),
                    "--request",
                    str(request_path),
                    "--intent",
                    str(authorization_intent_path),
                    "--holder",
                    str(holder),
                    "--password-fd",
                    "{password}",
                    "--output",
                    str(share_path),
                ],
                {"{password}": password},
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            authorization_share_paths.append(share_path)

        activation_path = root / "activation.json"
        arguments = [
            "aggregate-recovery-authorization",
            "--authority",
            str(authority_path),
            "--recovery",
            str(recovery_path),
            "--request",
            str(request_path),
            "--intent",
            str(authorization_intent_path),
            "--output",
            str(activation_path),
        ]
        for share_path in authorization_share_paths:
            arguments.extend(["--share", str(share_path)])
        result = self._invoke_rebirth_cli(arguments)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        retry = self._invoke_rebirth_cli(arguments)
        self.assertEqual(retry.returncode, 0, retry.stderr.decode())
        activation = json.loads(activation_path.read_bytes())
        validate_recovery_activation(activation, self.authority, request=request)

        public_paths = [
            *descriptors,
            intent_path,
            *recovery_share_paths,
            recovery_path,
            request_path,
            authorization_intent_path,
            *authorization_share_paths,
            activation_path,
        ]
        public_exchange = b"".join(path.read_bytes() for path in public_paths)
        for private_seed in recovery_seeds:
            self.assertNotIn(private_seed, public_exchange)
        for holder in (*recovery_holders, *root_holders):
            self.assertNotIn(str(holder).encode(), result.stdout)

    def test_synthetic_recovery_cli_runs_each_stage_in_a_distinct_process(self) -> None:
        root = self.root_path / "recovery-cli"
        root.mkdir(mode=0o700)
        authority_path = root / "authority.json"
        runtime_path = root / "runtime.json"
        profile_path = root / "profile.json"
        authority_path.write_bytes(canonical_bytes(self._authority_document()))
        runtime_path.write_bytes(canonical_bytes(self._base_runtime_bundle()))
        profile_path.write_bytes(
            canonical_bytes(
                {
                    "schema": "dm.operator.rebirth-target-profile/v1",
                    "label": "recovered-cli",
                    "body_ref": "cluster:recovered-cli:compaii",
                    "principal_id": "compaii@recovered-cli",
                    "listen_host": "127.0.0.1",
                    "listen_port": 28688,
                    "advertised_endpoint": "http://127.0.0.1:28688/dm-peer/v1",
                    "targets": [],
                }
            )
        )
        for path in (authority_path, runtime_path, profile_path):
            path.chmod(0o600)
        old_password = b"recovery-cli-old-password"
        new_password = b"recovery-cli-new-password"
        target_password = b"recovery-cli-target-password"
        old_custody = root / "old-root-custody.json"
        EncryptedKeystore.create(
            old_custody,
            lambda: bytearray(old_password),
            control_head=self.state.head,
            secrets={
                **{
                    f"root.signing.v1:{index}": value
                    for index, value in enumerate(self.root_seeds)
                },
                **{
                    f"recovery.signing.v1:{index}": seed(f"recovery-{label}")
                    for index, label in enumerate(("a", "b", "c"))
                },
            },
        )

        def invoke(
            arguments: list[str], passwords: dict[str, bytes]
        ) -> subprocess.CompletedProcess[bytes]:
            descriptors: dict[str, int] = {}
            writers: list[int] = []
            for marker, password in passwords.items():
                reader, writer = os.pipe()
                os.write(writer, password)
                os.close(writer)
                descriptors[marker] = reader
                writers.append(reader)
            try:
                return subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "daimon_matrix.operator_rebirth",
                        *[
                            str(descriptors[value]) if value in descriptors else value
                            for value in arguments
                        ],
                    ],
                    cwd=Path(__file__).resolve().parents[1],
                    env={
                        **os.environ,
                        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
                    },
                    pass_fds=tuple(descriptors.values()),
                    capture_output=True,
                    check=False,
                )
            finally:
                for descriptor in writers:
                    os.close(descriptor)

        recovered = invoke(
            [
                "synthetic-single-store-recover",
                "--authority",
                str(authority_path),
                "--root-custody",
                str(old_custody),
                "--current-password-fd",
                "{old}",
                "--replacement-password-fd",
                "{new}",
                "--output",
                str(root / "recovered-root"),
            ],
            {"{old}": old_password, "{new}": new_password},
        )
        assert recovered.returncode == 0, recovered.stderr.decode()
        recovery_path = root / "recovered-root/recovery.json"
        prepared = invoke(
            [
                "prepare-recovery",
                "--authority",
                str(authority_path),
                "--recovery",
                str(recovery_path),
                "--profile",
                str(profile_path),
                "--output",
                str(root / "target-preparation"),
                "--password-fd",
                "{target}",
            ],
            {"{target}": target_password},
        )
        assert prepared.returncode == 0, prepared.stderr.decode()
        request_path = root / "target-preparation/request.json"
        activation_path = root / "activation.json"
        authorized = invoke(
            [
                "synthetic-single-store-authorize-recovery",
                "--authority",
                str(authority_path),
                "--recovery",
                str(recovery_path),
                "--request",
                str(request_path),
                "--recovered-root-custody",
                str(root / "recovered-root/root-custody.json"),
                "--root-password-fd",
                "{new}",
                "--output",
                str(activation_path),
            ],
            {"{new}": new_password},
        )
        assert authorized.returncode == 0, authorized.stderr.decode()
        activated = invoke(
            [
                "activate-recovery",
                "--base-runtime",
                str(runtime_path),
                "--preparation-dir",
                str(root / "target-preparation"),
                "--request",
                str(request_path),
                "--activation",
                str(activation_path),
                "--output",
                str(root / "target-package"),
                "--password-fd",
                "{target}",
            ],
            {"{target}": target_password},
        )
        assert activated.returncode == 0, activated.stderr.decode()
        for result in (recovered, prepared, authorized, activated):
            combined = result.stdout + result.stderr
            assert old_password not in combined
            assert new_password not in combined
            assert target_password not in combined
        package = json.loads(
            (root / "target-package/runtime/runtime.json").read_bytes()
        )
        assert package["peer_transport"]["targets"] == []
        assert len(package["authority_history"]) == 1
