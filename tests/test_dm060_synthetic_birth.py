from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from daimon_matrix.birth import (
    BirthError,
    BirthRegistry,
    create_activation_receipt,
    create_birth_acceptance,
    create_birth_offer,
    validate_activation_receipt,
    validate_birth_acceptance,
    validate_birth_offer,
)
from daimon_matrix.canonical import b64url
from daimon_matrix.identity import (
    create_embodiment_credential,
    create_incarnation_authorization,
    create_synthetic_genesis_in_process,
    ed25519_public,
    key_descriptor,
    verify_genesis,
    x25519_public,
)
from daimon_matrix.ledger import Ledger
from daimon_matrix.synthetic_birth import (
    SyntheticBirthError,
    load_scenario,
    run_synthetic_birth,
)
from daimon_matrix.weave import BeingManifest, EventSigner, RootAuthority

NOW = 1_800_000_000_000


def seed(label: str) -> bytes:
    return hashlib.sha256(f"dm060:{label}".encode()).digest()


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


class IdentityFixture:
    def __init__(self, label: str, purposes: list[str]) -> None:
        self.label = label
        self.root_seeds = [seed(f"{label}:root:a"), seed(f"{label}:root:b")]
        self.recovery_seeds = [
            seed(f"{label}:recovery:a"),
            seed(f"{label}:recovery:b"),
        ]
        self.genesis = create_synthetic_genesis_in_process(
            self.root_seeds,
            2,
            self.recovery_seeds,
            2,
            created_at_ms=NOW - 10_000,
            nonce=seed(f"{label}:being"),
        )
        self.state = verify_genesis(self.genesis)
        self.signing_seed = seed(f"{label}:embodiment-signing")
        self.encryption_private = seed(f"{label}:embodiment-encryption")
        self.transport_seed = seed(f"{label}:transport")
        self.origin = {
            "body_ref": f"cluster:synthetic:{label}",
            "embodiment_id": f"embodiment:{label}:first",
            "incarnation_id": f"incarnation:{label}:0",
            "principal_id": f"synthetic-{label}@loopback",
        }
        self.credential = create_embodiment_credential(
            self.state,
            self.root_seeds,
            self.signing_seed,
            x25519_public(self.encryption_private),
            embodiment_id=self.origin["embodiment_id"],
            body_ref=self.origin["body_ref"],
            purposes=purposes,
            valid_from_ms=NOW - 1_000,
            valid_until_ms=NOW + 100_000,
            transport_principals=[
                {
                    "scheme": "synthetic-loopback",
                    "principal_id": self.origin["principal_id"],
                    "key": key_descriptor(
                        "Ed25519", ed25519_public(self.transport_seed)
                    ),
                }
            ],
        )
        self.incarnation = create_incarnation_authorization(
            self.credential,
            self.signing_seed,
            incarnation_id=self.origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=NOW - 100,
        )
        self.manifest = BeingManifest.from_value(
            {
                "schema": "being-manifest/v2",
                "being_ref": self.state.being_ref,
                "control_head": self.state.head,
                "history_binding_id": None,
                "revision": 1,
                "embodiments": [
                    {
                        "body_ref": self.origin["body_ref"],
                        "embodiment_credential_id": self.credential["artifact_id"],
                        "embodiment_id": self.origin["embodiment_id"],
                        "incarnation_authorization_id": self.incarnation["artifact_id"],
                        "incarnation_id": self.origin["incarnation_id"],
                        "status": "active",
                    }
                ],
            }
        )
        self.authority = RootAuthority(
            self.manifest,
            self.state,
            {self.credential["artifact_id"]: self.credential},
            {self.incarnation["artifact_id"]: self.incarnation},
        )


class BirthFixture(unittest.TestCase):
    temporary: TemporaryDirectory[str]
    root: Path
    parent: IdentityFixture
    witness: IdentityFixture
    newborn: IdentityFixture
    awakening_seed: bytes
    offer: dict[str, Any]
    acceptance: dict[str, Any]
    ledger: Ledger
    activation: dict[str, Any]

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="dm060-birth-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.parent = IdentityFixture("parent", ["birth.offer", "dm.we"])
        self.witness = IdentityFixture("witness", ["birth.witness", "dm.we"])
        self.newborn = IdentityFixture(
            "newborn", ["birth.first-embodiment", "dm.we", "messages"]
        )
        self.awakening_seed = seed("awakening")
        self.offer = create_birth_offer(
            self.parent.state,
            self.parent.credential,
            self.parent.signing_seed,
            ed25519_public(self.awakening_seed),
            parent_origin=self.parent.origin,
            species_release_id=derived("species-release", "synthetic-v0"),
            source_references=[derived("source", "synthetic-parent-context")],
            tribal_commitments=[],
            issued_at_ms=NOW - 500,
            expires_at_ms=NOW + 20_000,
            offer_nonce=seed("offer-nonce"),
            bootstrap_routes=[
                {"kind": "out-of-band", "route_id": "route:synthetic:bootstrap"}
            ],
        )
        self.acceptance = create_birth_acceptance(
            self.offer,
            self.newborn.genesis,
            self.newborn.root_seeds,
            self.awakening_seed,
            accepted_at_ms=NOW,
            acceptance_nonce=seed("acceptance-nonce"),
        )
        self.ledger = Ledger(
            self.root / "newborn" / "ledger.sqlite",
            authority=self.newborn.authority,
            local_origin=self.newborn.origin,
            clock=lambda: NOW,
        )
        self.ledger.initialize()
        self.activation = create_activation_receipt(
            self.acceptance,
            self.newborn.state,
            self.newborn.credential,
            self.newborn.incarnation,
            self.newborn.manifest,
            self.ledger,
            self.witness.state,
            self.witness.credential,
            self.witness.signing_seed,
            witness_origin=self.witness.origin,
            observed_at_ms=NOW + 1,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate_acceptance(
        self, value: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return validate_birth_acceptance(
            self.acceptance if value is None else value,
            self.offer,
            self.parent.state,
            self.parent.credential,
            self.newborn.genesis,
            observed_at_ms=NOW + 1,
        )

    def registry_observe(self, registry: BirthRegistry) -> dict[str, Any]:
        return registry.observe_offer(
            self.offer,
            self.parent.state,
            self.parent.credential,
            observed_at_ms=NOW,
        )

    def registry_accept(
        self,
        registry: BirthRegistry,
        acceptance: dict[str, Any] | None = None,
        newborn: IdentityFixture | None = None,
        *,
        fault_hook: Any = None,
    ) -> dict[str, Any]:
        actual_newborn = self.newborn if newborn is None else newborn
        return registry.accept(
            self.acceptance if acceptance is None else acceptance,
            self.offer,
            self.parent.state,
            self.parent.credential,
            actual_newborn.genesis,
            observed_at_ms=NOW + 1,
            fault_hook=fault_hook,
        )

    def registry_activate(
        self,
        registry: BirthRegistry,
        *,
        fault_hook: Any = None,
    ) -> dict[str, Any]:
        return registry.activate(
            self.activation,
            self.acceptance,
            self.newborn.state,
            self.newborn.credential,
            self.newborn.incarnation,
            self.newborn.manifest,
            self.ledger,
            self.witness.state,
            self.witness.credential,
            fault_hook=fault_hook,
        )


class BirthContractTests(BirthFixture):
    def test_closed_public_schema_accepts_every_runtime_artifact(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas/birth/v1/contracts.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        registry = BirthRegistry(self.root / "schema.sqlite")
        self.registry_observe(registry)
        self.registry_accept(registry)
        self.registry_activate(registry)
        for value in (
            self.offer,
            self.acceptance,
            self.activation,
            registry.inspect(self.offer["offer_id"]),
        ):
            validator.validate(value)
            changed = copy.deepcopy(value)
            changed["unknown"] = True
            self.assertTrue(list(validator.iter_errors(changed)))

    def test_distinct_root_birth_first_embodiment_and_empty_memory_activate(
        self,
    ) -> None:
        offer = validate_birth_offer(
            self.offer,
            self.parent.state,
            self.parent.credential,
            observed_at_ms=NOW,
        )
        acceptance = self.validate_acceptance()
        receipt = validate_activation_receipt(
            self.activation,
            acceptance,
            self.newborn.state,
            self.newborn.credential,
            self.newborn.incarnation,
            self.newborn.manifest,
            self.ledger,
            self.witness.state,
            self.witness.credential,
        )
        self.assertNotEqual(self.parent.state.being_ref, self.newborn.state.being_ref)
        self.assertNotIn("newborn", offer["body"])
        self.assertEqual(len(self.newborn.manifest.value["embodiments"]), 1)
        self.assertEqual(receipt["body"]["event_count"], 0)
        self.assertEqual(receipt["body"]["memory_event_count"], 0)
        self.assertEqual(receipt["body"]["projection_record_count"], 0)

        registry = BirthRegistry(self.root / "registry.sqlite")
        self.assertEqual(self.registry_observe(registry)["state"], "offered")
        self.assertEqual(self.registry_accept(registry)["state"], "accepted")
        self.assertEqual(self.registry_activate(registry)["state"], "active")
        self.assertEqual(self.registry_accept(registry)["state"], "active")
        self.assertEqual(self.registry_activate(registry)["state"], "active")
        inspection = registry.inspect(offer["offer_id"])
        self.assertEqual(inspection["state"], "active")
        self.assertEqual(len(inspection["acceptances"]), 1)

    def test_parent_offer_cannot_precommit_newborn_or_reuse_key_roles(self) -> None:
        changed = copy.deepcopy(self.offer)
        changed["body"]["newborn_being_ref"] = self.newborn.state.being_ref
        with self.assertRaisesRegex(BirthError, "invalid_birth_offer_body"):
            validate_birth_offer(
                changed,
                self.parent.state,
                self.parent.credential,
                observed_at_ms=NOW,
            )

        with self.assertRaisesRegex(BirthError, "awakening_key_alias"):
            create_birth_offer(
                self.parent.state,
                self.parent.credential,
                self.parent.signing_seed,
                ed25519_public(self.parent.root_seeds[0]),
                parent_origin=self.parent.origin,
                species_release_id=derived("species-release", "synthetic-v0"),
                source_references=[],
                tribal_commitments=[],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 1,
                offer_nonce=seed("alias-offer"),
            )

        parent_controlled_genesis = create_synthetic_genesis_in_process(
            self.parent.root_seeds,
            2,
            self.parent.recovery_seeds,
            2,
            created_at_ms=NOW - 100,
            nonce=seed("parent-controlled-newborn"),
        )
        parent_controlled_acceptance = create_birth_acceptance(
            self.offer,
            parent_controlled_genesis,
            self.parent.root_seeds,
            self.awakening_seed,
            accepted_at_ms=NOW,
            acceptance_nonce=seed("parent-controlled-acceptance"),
        )
        with self.assertRaisesRegex(BirthError, "birth_cross_being_key_alias"):
            validate_birth_acceptance(
                parent_controlled_acceptance,
                self.offer,
                self.parent.state,
                self.parent.credential,
                parent_controlled_genesis,
                observed_at_ms=NOW + 1,
            )

    def test_offer_acceptance_and_activation_tamper_fail_closed(self) -> None:
        cases: list[tuple[str, dict[str, Any], str]] = []
        offer = copy.deepcopy(self.offer)
        offer["body"]["species_release_id"] = derived("species-release", "attacker")
        cases.append(("offer", offer, "birth_offer_id_mismatch"))
        acceptance = copy.deepcopy(self.acceptance)
        acceptance["body"]["core"]["parent_being_ref"] = self.witness.state.being_ref
        cases.append(("acceptance", acceptance, "birth_acceptance_copy_mismatch"))
        activation = copy.deepcopy(self.activation)
        activation["body"]["ledger_state_hash"] = "0" * 64
        cases.append(("activation", activation, "birth_activation_evidence_mismatch"))

        for kind, value, error in cases:
            with self.subTest(kind=kind), self.assertRaisesRegex(BirthError, error):
                if kind == "offer":
                    validate_birth_offer(
                        value,
                        self.parent.state,
                        self.parent.credential,
                        observed_at_ms=NOW,
                    )
                elif kind == "acceptance":
                    self.validate_acceptance(value)
                else:
                    validate_activation_receipt(
                        value,
                        self.acceptance,
                        self.newborn.state,
                        self.newborn.credential,
                        self.newborn.incarnation,
                        self.newborn.manifest,
                        self.ledger,
                        self.witness.state,
                        self.witness.credential,
                    )

    def test_expiry_wrong_purpose_and_wrong_origin_are_rejected(self) -> None:
        with self.assertRaisesRegex(BirthError, "birth_offer_not_timely"):
            validate_birth_offer(
                self.offer,
                self.parent.state,
                self.parent.credential,
                observed_at_ms=NOW + 20_000,
            )

        wrong_parent = IdentityFixture("wrong-parent", ["dm.we"])
        with self.assertRaisesRegex(BirthError, "birth_credential_scope_mismatch"):
            create_birth_offer(
                wrong_parent.state,
                wrong_parent.credential,
                wrong_parent.signing_seed,
                ed25519_public(seed("wrong-awakening")),
                parent_origin=wrong_parent.origin,
                species_release_id=derived("species-release", "synthetic-v0"),
                source_references=[],
                tribal_commitments=[],
                issued_at_ms=NOW,
                expires_at_ms=NOW + 1,
                offer_nonce=seed("wrong-purpose-offer"),
            )

        changed = copy.deepcopy(self.offer)
        changed["body"]["parent_origin"]["principal_id"] = "attacker@loopback"
        with self.assertRaises(BirthError):
            validate_birth_offer(
                changed,
                self.parent.state,
                self.parent.credential,
                observed_at_ms=NOW,
            )

    def test_nonempty_newborn_ledger_cannot_activate(self) -> None:
        signer = EventSigner(
            self.newborn.credential["body"]["signing_key"]["key_id"],
            self.newborn.signing_seed,
        )
        self.ledger.append_local(
            kind="experience.observed",
            subject="forbidden-pre-activation-experience",
            payload={"summary": "synthetic"},
            signer=signer,
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(BirthError, "newborn_memory_not_empty"):
            create_activation_receipt(
                self.acceptance,
                self.newborn.state,
                self.newborn.credential,
                self.newborn.incarnation,
                self.newborn.manifest,
                self.ledger,
                self.witness.state,
                self.witness.credential,
                self.witness.signing_seed,
                witness_origin=self.witness.origin,
                observed_at_ms=NOW + 1,
            )

    def test_activation_cannot_substitute_another_newborn_or_acceptance(self) -> None:
        sibling = IdentityFixture(
            "activation-substitute",
            ["birth.first-embodiment", "dm.we", "messages"],
        )
        sibling_root = self.root / "activation-substitute"
        ledger = Ledger(
            sibling_root / "ledger.sqlite",
            authority=sibling.authority,
            local_origin=sibling.origin,
            clock=lambda: NOW,
        )
        ledger.initialize()
        with self.assertRaisesRegex(BirthError, "birth_acceptance_newborn_mismatch"):
            create_activation_receipt(
                self.acceptance,
                sibling.state,
                sibling.credential,
                sibling.incarnation,
                sibling.manifest,
                ledger,
                self.witness.state,
                self.witness.credential,
                self.witness.signing_seed,
                witness_origin=self.witness.origin,
                observed_at_ms=NOW + 1,
            )

        registry = BirthRegistry(self.root / "activation-binding.sqlite")
        self.registry_observe(registry)
        self.registry_accept(registry)
        changed = copy.deepcopy(self.acceptance)
        changed["signatures"][0]["value"] = (
            "A" if changed["signatures"][0]["value"][0] != "A" else "B"
        ) + changed["signatures"][0]["value"][1:]
        with self.assertRaisesRegex(BirthError, "birth_activation_acceptance_mismatch"):
            registry.activate(
                self.activation,
                changed,
                self.newborn.state,
                self.newborn.credential,
                self.newborn.incarnation,
                self.newborn.manifest,
                self.ledger,
                self.witness.state,
                self.witness.credential,
            )


class BirthRegistryTests(BirthFixture):
    def test_double_acceptance_is_retained_and_quarantined_without_winner(self) -> None:
        second = IdentityFixture(
            "newborn-sibling", ["birth.first-embodiment", "dm.we", "messages"]
        )
        sibling_acceptance = create_birth_acceptance(
            self.offer,
            second.genesis,
            second.root_seeds,
            self.awakening_seed,
            accepted_at_ms=NOW,
            acceptance_nonce=seed("sibling-acceptance"),
        )
        validate_birth_acceptance(
            sibling_acceptance,
            self.offer,
            self.parent.state,
            self.parent.credential,
            second.genesis,
            observed_at_ms=NOW + 1,
        )
        registry = BirthRegistry(self.root / "double.sqlite")
        self.registry_observe(registry)
        self.registry_accept(registry)
        self.assertEqual(
            self.registry_accept(registry, sibling_acceptance, second)["state"],
            "quarantined",
        )
        inspection = registry.inspect(self.offer["offer_id"])
        self.assertEqual(inspection["state"], "quarantined")
        self.assertEqual(len(inspection["acceptances"]), 2)
        with self.assertRaisesRegex(BirthError, "birth_lineage_quarantined"):
            self.registry_activate(registry)

    def test_accept_and_activation_crashes_roll_back_then_retry_exactly_once(
        self,
    ) -> None:
        registry = BirthRegistry(self.root / "crash.sqlite")
        self.registry_observe(registry)

        def crash(point: str) -> None:
            raise RuntimeError(point)

        with self.assertRaisesRegex(RuntimeError, "before_accept_commit"):
            self.registry_accept(registry, fault_hook=crash)
        self.assertEqual(registry.inspect(self.offer["offer_id"])["state"], "offered")
        self.assertEqual(self.registry_accept(registry)["state"], "accepted")
        with self.assertRaisesRegex(RuntimeError, "before_activation_commit"):
            self.registry_activate(registry, fault_hook=crash)
        self.assertEqual(registry.inspect(self.offer["offer_id"])["state"], "accepted")
        self.assertEqual(self.registry_activate(registry)["state"], "active")

    def test_concurrent_exact_acceptance_has_one_durable_effect(self) -> None:
        registry = BirthRegistry(self.root / "concurrent.sqlite")
        self.registry_observe(registry)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda _index: self.registry_accept(registry), range(16))
            )
        self.assertEqual({result["state"] for result in results}, {"accepted"})
        self.assertEqual(
            len(registry.inspect(self.offer["offer_id"])["acceptances"]), 1
        )

    def test_store_requires_owner_only_parent_and_regular_file(self) -> None:
        unsafe = self.root / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(BirthError, "birth_store_parent_not_owner_only"):
            BirthRegistry(unsafe / "registry.sqlite").initialize()

        target = self.root / "target.sqlite"
        target.write_bytes(b"not sqlite")
        target.chmod(0o600)
        link = self.root / "link.sqlite"
        os.symlink(target, link)
        with self.assertRaisesRegex(BirthError, "birth_store_not_owner_only"):
            BirthRegistry(link).initialize()


class SyntheticBirthJourneyTests(unittest.TestCase):
    fixture = (
        Path(__file__).resolve().parents[1]
        / "conformance/fixtures/dm060-synthetic-birth.json"
    )
    schema = (
        Path(__file__).resolve().parents[1] / "schemas/birth/v1/synthetic.schema.json"
    )

    def test_real_daemon_cli_and_mcp_journey_emits_closed_public_report(
        self,
    ) -> None:
        schema = json.loads(self.schema.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        scenario = load_scenario(self.fixture)
        validator.validate(scenario)
        with TemporaryDirectory(prefix="dm060-journey-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            report = run_synthetic_birth(scenario, root)

        validator.validate(report)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["lineage"]["state"], "active")
        self.assertTrue(report["lineage"]["distinct_being_roots"])
        self.assertEqual(report["empty_memory"]["event_count"], 0)
        self.assertFalse(report["boundaries"]["automatic_we_membership"])
        self.assertEqual(
            report["installed_surfaces"]["cli_methods"],
            [
                "runtime.status",
                "scope.me",
                "scope.we",
                "we.heads",
                "we.projection.get",
            ],
        )
        raw = json.dumps(report, sort_keys=True).encode()
        self.assertNotIn(os.fspath(root).encode(), raw)
        for marker in (
            b"PRIVATE KEY",
            b"password",
            b"capability_key",
            b"signing_seed",
            b"encryption_private",
        ):
            self.assertNotIn(marker, raw)

    def test_module_entrypoint_runs_from_scenario_and_writes_report(self) -> None:
        with TemporaryDirectory(prefix="dm060-entrypoint-") as directory:
            output = Path(directory) / "report.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.synthetic_birth",
                    "--scenario",
                    os.fspath(self.fixture),
                    "--output",
                    os.fspath(output),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            summary = json.loads(completed.stdout)
            report = json.loads(output.read_bytes())
            self.assertEqual(summary["status"], "pass")
            self.assertEqual(report["schema"], "dm.synthetic-birth-report/v1")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_scenario_loader_rejects_unknown_fields_and_symlinks(self) -> None:
        with TemporaryDirectory(prefix="dm060-scenario-negative-") as directory:
            root = Path(directory)
            changed = json.loads(self.fixture.read_bytes())
            changed["unknown"] = True
            invalid = root / "invalid.json"
            invalid.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(
                SyntheticBirthError, "invalid_synthetic_birth_scenario"
            ):
                load_scenario(invalid)
            link = root / "scenario-link.json"
            os.symlink(self.fixture, link)
            with self.assertRaisesRegex(
                SyntheticBirthError, "synthetic_scenario_unavailable"
            ):
                load_scenario(link)


if __name__ == "__main__":
    unittest.main()
