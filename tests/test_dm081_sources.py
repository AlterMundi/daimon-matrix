from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path
from typing import Any
from unittest import mock

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import b64url, canonical_bytes, digest
from daimon_matrix.conformance import _test_exists
from daimon_matrix.local_api import create_capability, create_request
from daimon_matrix.runtime import RuntimeError as HostedRuntimeError
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import SOURCE_METHODS, HostedWeave
from daimon_matrix.sources import (
    ASSESSMENT_EVENT_KIND,
    CLAIM_EVENT_KIND,
    SourceCAS,
    SourceError,
    SourceRegistry,
    SourceServiceContext,
    assessment_series_id,
    claim_series_id,
    import_series_id,
    provenance_node_id,
    publication_binding_hash,
    publication_id,
    source_claim_binding_hash,
    source_content_ref,
    source_id,
    source_selector,
    validate_assessment_payload,
    validate_claim_payload,
    validate_content_ref,
    validate_evidence_manifest,
    validate_import_payload,
    validate_policy_snapshot,
    validate_provenance_manifest,
    validate_publication_payload,
    validate_source_core,
    validate_source_event_payload,
    validate_source_selector,
)
from daimon_matrix.sources import _canonical as source_canonical
from daimon_matrix.synthetic_sources import run_synthetic_sources
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm081_vectors import generate as generate_dm081_vectors

ME = "me:dm081-alice"
OTHER = "me:dm081-bob"
EMBODIMENT = "embodiment:dm081"
INCARNATION = "incarnation:dm081"
MANIFEST_HASH = "11" * 32
CLAIM_EVENT_ID = "10000000-0000-4000-8000-000000000001"
CLAIM_EVENT_HASH = "22" * 32
PUBLICATION_EVENT_ID = "10000000-0000-4000-8000-000000000002"
PUBLICATION_EVENT_HASH = "33" * 32
CURSOR_EVENT_ID = "10000000-0000-4000-8000-000000000003"
CURSOR_EVENT_HASH = "44" * 32
ROOT = Path(__file__).resolve().parents[1]


def runtime_contract_validator() -> Draft202012Validator:
    schemas = [
        json.loads((ROOT / relative).read_bytes())
        for relative in (
            "schemas/source/v0/contracts.schema.json",
            "schemas/source/v0/runtime.schema.json",
            "schemas/weave/v1/event.schema.json",
        )
    ]
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas
    )
    for schema in schemas:
        Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schemas[1], registry=registry, format_checker=FormatChecker()
    )


def jcs_ref(value: Any, media_type: str = "application/json") -> dict[str, Any]:
    return source_content_ref(canonical_bytes(value), media_type)


def source_core(reference: str = "source:dm081:shared") -> dict[str, str]:
    return {
        "canonical_reference": reference,
        "kind": "project",
        "namespace": "dm081-test",
        "schema": "daimon-source-core/v0",
    }


def control_position() -> dict[str, str]:
    return {
        "embodiment_id": EMBODIMENT,
        "incarnation_id": INCARNATION,
        "manifest_hash": MANIFEST_HASH,
    }


def claim_payload(
    *,
    claimant: str = ME,
    sequence: int = 0,
    previous_id: str | None = None,
    previous_hash: str | None = None,
    action: str = "assert",
) -> dict[str, Any]:
    core = source_core()
    identifier = source_id(core)
    placeholder = source_content_ref(b"evidence", "application/octet-stream")
    return {
        "action": action,
        "claim_sequence": sequence,
        "claim_series_id": claim_series_id(claimant, identifier),
        "claimant_control_position": control_position(),
        "claimant_me_id": claimant,
        "evidence_manifest_ref": placeholder if action == "assert" else None,
        "expires_at_ms": 2_000 if action == "assert" else None,
        "issued_at_ms": 1_000,
        "previous_claim_event_hash": previous_hash,
        "previous_claim_event_id": previous_id,
        "relations": ["created-by", "influenced-by"],
        "schema": "daimon-source-claim/v0",
        "source_core": core,
        "source_id": identifier,
    }


def evidence_manifest(claim: dict[str, Any]) -> dict[str, Any]:
    evidence = source_content_ref(b"corroborating evidence", "text/plain")
    return {
        "claim_binding_hash": source_claim_binding_hash(claim),
        "entries": [
            {
                "artifact": None,
                "assertion": "external-metadata",
                "content": evidence,
                "evidence_id": evidence["content_id"],
                "issuer_me_id": None,
                "kind": "content",
                "role": "corroborates",
            }
        ],
        "schema": "daimon-source-evidence-manifest/v0",
    }


def publication_payload(claim: dict[str, Any]) -> dict[str, Any]:
    uri = "hmk://dm081/chapters/1"
    content = source_content_ref(b"published knowledge", "text/plain")
    placeholder = source_content_ref(b"provenance", "application/json")
    return {
        "action": "publish",
        "classification": "public",
        "consent": "explicit",
        "content_ref": content,
        "issued_at_ms": 3_000,
        "license": "CC BY-SA 4.0",
        "previous_publication_event_hash": None,
        "previous_publication_event_id": None,
        "provenance_manifest_ref": placeholder,
        "publication_id": publication_id(ME, uri),
        "publication_sequence": 0,
        "publisher_claim_event_id": CLAIM_EVENT_ID,
        "publisher_me_id": ME,
        "reason": None,
        "schema": "daimon-source-publication/v0",
        "source_id": claim["source_id"],
        "source_uri": uri,
    }


def provenance_manifest(publication: dict[str, Any]) -> dict[str, Any]:
    original = {
        "authors": [
            {
                "assertion": "publisher-declared",
                "evidence_refs": [],
                "subject_id": "external:alice",
                "subject_kind": "external",
            }
        ],
        "content_ref": source_content_ref(b"notes", "text/plain"),
        "kind": "original",
        "node_id": "placeholder",
        "source_uri": "urn:dm081:notes",
    }
    original["node_id"] = provenance_node_id(original)
    output = {
        "authors": copy.deepcopy(original["authors"]),
        "content_ref": copy.deepcopy(publication["content_ref"]),
        "kind": "derivation",
        "node_id": "placeholder",
        "source_uri": publication["source_uri"],
    }
    output["node_id"] = provenance_node_id(output)
    nodes = sorted([original, output], key=lambda row: row["node_id"])
    edge = {
        "from_node_id": original["node_id"],
        "relation": "derived-from",
        "to_node_id": output["node_id"],
        "transformation_ref": None,
    }
    return {
        "edges": [edge],
        "nodes": nodes,
        "output_node_id": output["node_id"],
        "publication_binding_hash": publication_binding_hash(publication),
        "schema": "daimon-source-provenance-manifest/v0",
    }


def policy_snapshot(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_refs": [],
        "claim_event_ids": [CLAIM_EVENT_ID],
        "content_refs": [copy.deepcopy(claim["evidence_manifest_ref"])],
        "contradiction_refs": [],
        "observed_cursor_event_hash": CURSOR_EVENT_HASH,
        "observed_cursor_event_id": CURSOR_EVENT_ID,
        "schema": "daimon-source-policy-evidence-snapshot/v0",
        "source_id": claim["source_id"],
        "subject": {
            "event_hash": CLAIM_EVENT_HASH,
            "event_id": CLAIM_EVENT_ID,
            "id": claim["claim_series_id"],
            "kind": "claim",
        },
    }


class SourceWireContractTests(unittest.TestCase):
    def test_source_graph_depth_accepts_exact_bound_and_rejects_plus_one(
        self,
    ) -> None:
        exact: dict[str, Any] = {}
        for _ in range(64):
            exact = {"nested": exact}
        self.assertEqual(
            source_canonical(exact, "source_depth"), canonical_bytes(exact)
        )

        over: dict[str, Any] = exact
        over = {"nested": over}
        with self.assertRaisesRegex(SourceError, "source_depth"):
            source_canonical(over, "source_depth")

        exact_ref = source_content_ref(b"bound", "application/octet-stream")
        exact_ref["byte_length"] = 67_108_864
        self.assertEqual(validate_content_ref(exact_ref), exact_ref)
        over_ref = {**exact_ref, "byte_length": 67_108_865}
        with self.assertRaisesRegex(SourceError, "source_content_size"):
            validate_content_ref(over_ref)

    def test_published_schema_enforces_action_and_sequence_discriminators(self) -> None:
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/source/v0/contracts.schema.json"
            ).read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        claim = claim_payload()
        validator.validate(claim)
        missing_evidence = copy.deepcopy(claim)
        missing_evidence["evidence_manifest_ref"] = None
        with self.assertRaises(ValidationError):
            validator.validate(missing_evidence)

        publication = publication_payload(claim)
        validator.validate(publication)
        invalid_tombstone = {
            **copy.deepcopy(publication),
            "action": "tombstone",
            "publication_sequence": 1,
            "previous_publication_event_id": PUBLICATION_EVENT_ID,
            "previous_publication_event_hash": PUBLICATION_EVENT_HASH,
            "reason": "withdrawn",
        }
        with self.assertRaises(ValidationError):
            validator.validate(invalid_tombstone)

        valid_tombstone = {
            **invalid_tombstone,
            "classification": None,
            "consent": None,
            "content_ref": None,
            "license": None,
            "provenance_manifest_ref": None,
        }
        validator.validate(valid_tombstone)

    def test_source_identity_is_byte_exact_and_selector_bound(self) -> None:
        core = source_core()
        identifier = source_id(core)
        self.assertEqual(validate_source_core(core), core)
        self.assertEqual(
            validate_source_selector(source_selector(core))["source_id"], identifier
        )
        self.assertNotEqual(identifier, source_id(source_core("source:dm081:Shared")))

        unsafe = source_core("https://user@example.test/source")
        with self.assertRaisesRegex(SourceError, "unsafe_source_core"):
            validate_source_core(unsafe)

        selector = source_selector(core)
        selector["source_core_hash"] = b64url(hashlib.sha256(b"other").digest())
        with self.assertRaisesRegex(SourceError, "source_selector_mismatch"):
            validate_source_selector(selector)

    def test_claim_binding_and_evidence_are_closed_and_content_bound(self) -> None:
        claim = claim_payload()
        self.assertEqual(validate_claim_payload(claim), claim)
        manifest = evidence_manifest(claim)
        self.assertEqual(validate_evidence_manifest(manifest, claim), manifest)

        changed = copy.deepcopy(claim)
        changed["relations"] = ["created-by"]
        with self.assertRaisesRegex(SourceError, "claim_binding_hash_mismatch"):
            validate_evidence_manifest(manifest, changed)

        unproved_crypto = copy.deepcopy(manifest)
        unproved_crypto["entries"][0]["assertion"] = "cryptographically-authored"
        unproved_crypto["entries"][0]["issuer_me_id"] = ME
        with self.assertRaisesRegex(
            SourceError, "cryptographic_evidence_proof_required"
        ):
            validate_evidence_manifest(unproved_crypto, claim)

    def test_false_self_retraction_and_predecessor_rules_fail_closed(self) -> None:
        claim = claim_payload()
        with self.assertRaisesRegex(SourceError, "false_source_self"):
            validate_source_event_payload(
                CLAIM_EVENT_KIND,
                claim,
                author_me_id=OTHER,
                origin={
                    "embodiment_id": EMBODIMENT,
                    "incarnation_id": INCARNATION,
                },
                manifest_hash=MANIFEST_HASH,
                causal_parents=[],
            )

        retraction = claim_payload(
            sequence=1,
            previous_id=CLAIM_EVENT_ID,
            previous_hash=CLAIM_EVENT_HASH,
            action="retract",
        )
        self.assertEqual(validate_claim_payload(retraction), retraction)
        with self.assertRaisesRegex(SourceError, "source_predecessor_not_causal"):
            validate_source_event_payload(
                CLAIM_EVENT_KIND,
                retraction,
                author_me_id=ME,
                origin={
                    "embodiment_id": EMBODIMENT,
                    "incarnation_id": INCARNATION,
                },
                manifest_hash=MANIFEST_HASH,
                causal_parents=[],
            )

    def test_assessment_is_local_attributed_and_snapshot_complete(self) -> None:
        claim = claim_payload()
        snapshot = policy_snapshot(claim)
        self.assertEqual(validate_policy_snapshot(snapshot), snapshot)
        assessment = {
            "assessment_sequence": 0,
            "assessment_series_id": assessment_series_id(
                OTHER, claim["claim_series_id"]
            ),
            "assessor_me_id": OTHER,
            "claim_event_hash": CLAIM_EVENT_HASH,
            "claim_event_id": CLAIM_EVENT_ID,
            "claimant_me_id": ME,
            "decided_at_ms": 4_000,
            "disposition": "admitted",
            "evidence_manifest_ref": claim["evidence_manifest_ref"],
            "evidence_snapshot_ref": jcs_ref(snapshot),
            "policy_ref": jcs_ref({"allow": True}),
            "previous_assessment_event_id": None,
            "reason_codes": ["admitted:evidence-satisfied"],
            "schema": "daimon-source-assessment/v0",
            "source_id": claim["source_id"],
        }
        self.assertEqual(validate_assessment_payload(assessment), assessment)
        with self.assertRaisesRegex(SourceError, "false_source_self"):
            validate_source_event_payload(
                ASSESSMENT_EVENT_KIND,
                assessment,
                author_me_id=ME,
                origin={},
                manifest_hash=MANIFEST_HASH,
                causal_parents=[CLAIM_EVENT_ID],
            )

    def test_publication_and_provenance_preserve_external_authorship(self) -> None:
        claim = claim_payload()
        publication = publication_payload(claim)
        self.assertEqual(validate_publication_payload(publication), publication)
        provenance = provenance_manifest(publication)
        self.assertEqual(
            validate_provenance_manifest(provenance, publication), provenance
        )

        forged = copy.deepcopy(provenance)
        forged["nodes"][0]["authors"][0]["assertion"] = "cryptographic"
        with self.assertRaises(SourceError):
            validate_provenance_manifest(forged, publication)

        unsafe = copy.deepcopy(publication)
        unsafe["source_uri"] = "https://user:secret@example.test/chapter"
        with self.assertRaisesRegex(SourceError, "invalid_source_uri"):
            validate_publication_payload(unsafe)

    def test_cyclic_and_disconnected_provenance_is_rejected(self) -> None:
        publication = publication_payload(claim_payload())
        provenance = provenance_manifest(publication)
        reverse = copy.deepcopy(provenance["edges"][0])
        reverse["from_node_id"], reverse["to_node_id"] = (
            reverse["to_node_id"],
            reverse["from_node_id"],
        )
        provenance["edges"] = sorted(
            [provenance["edges"][0], reverse], key=canonical_bytes
        )
        with self.assertRaisesRegex(SourceError, "provenance_cycle"):
            validate_provenance_manifest(provenance, publication)

    def test_initial_import_is_quarantine_and_promotion_is_separate(self) -> None:
        claim = claim_payload()
        publication = publication_payload(claim)
        snapshot = policy_snapshot(claim)
        policy_ref = jcs_ref({"target": "external-reference"})
        base = {
            "content_ref": publication["content_ref"],
            "decided_at_ms": 5_000,
            "decision": "quarantined",
            "decision_sequence": 0,
            "decision_series_id": import_series_id(
                OTHER, publication["publication_id"]
            ),
            "evidence_snapshot_ref": jcs_ref(snapshot),
            "policy_ref": policy_ref,
            "previous_decision_event_id": None,
            "provenance_manifest_ref": publication["provenance_manifest_ref"],
            "publication_event_hash": PUBLICATION_EVENT_HASH,
            "publication_event_id": PUBLICATION_EVENT_ID,
            "publication_id": publication["publication_id"],
            "reason_codes": ["quarantined:initial-pull"],
            "receiver_me_id": OTHER,
            "schema": "daimon-source-import-decision/v0",
            "source_claim_event_ids": [CLAIM_EVENT_ID],
            "source_id": claim["source_id"],
            "target_memory_category": None,
        }
        self.assertEqual(validate_import_payload(base), base)

        invalid = copy.deepcopy(base)
        invalid["decision"] = "promoted"
        invalid["target_memory_category"] = "external-reference"
        with self.assertRaisesRegex(SourceError, "invalid_initial_import_decision"):
            validate_import_payload(invalid)

        promoted = copy.deepcopy(invalid)
        promoted["decision_sequence"] = 1
        promoted["previous_decision_event_id"] = str(uuid.uuid4())
        promoted["reason_codes"] = ["promoted:policy-and-review-satisfied"]
        self.assertEqual(validate_import_payload(promoted), promoted)

        exact_reasons = copy.deepcopy(base)
        exact_reasons["reason_codes"] = [
            f"quarantined:bound-{index:02d}" for index in range(64)
        ]
        self.assertEqual(validate_import_payload(exact_reasons), exact_reasons)
        over_reasons = copy.deepcopy(exact_reasons)
        over_reasons["reason_codes"].append("quarantined:bound-over")
        with self.assertRaisesRegex(SourceError, "invalid_source_reason_codes"):
            validate_import_payload(over_reasons)


class SourceCASTests(unittest.TestCase):
    def test_exact_bytes_are_owner_local_idempotent_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cas = SourceCAS(Path(directory) / "source-cas.sqlite3")
            reference = cas.put(b"exact bytes", "text/plain")
            self.assertEqual(cas.put(b"exact bytes", "text/plain"), reference)
            self.assertEqual(cas.get(reference), b"exact bytes")
            self.assertTrue(cas.has(reference))
            self.assertEqual(
                (Path(directory) / "source-cas.sqlite3").stat().st_mode & 0o777, 0o600
            )

            missing = source_content_ref(b"missing", "text/plain")
            self.assertFalse(cas.has(missing))
            with self.assertRaisesRegex(SourceError, "source_content_missing"):
                cas.get(missing)

    def test_content_is_inert_without_network_execution_or_archive_expansion(
        self,
    ) -> None:
        hostile = (
            b"https://169.254.169.254/latest/meta-data/ ../../escape "
            b"$(touch pwned) <script>fetch('https://example.test')</script>"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cas = SourceCAS(root / "source-cas.sqlite3")
            with (
                mock.patch(
                    "socket.create_connection",
                    side_effect=AssertionError("network attempted"),
                ),
                mock.patch(
                    "subprocess.Popen",
                    side_effect=AssertionError("execution attempted"),
                ),
            ):
                reference = cas.put(hostile, "application/zip")
                self.assertEqual(cas.get(reference), hostile)
            self.assertFalse((root / "escape").exists())
            self.assertFalse((root / "pwned").exists())


class SourceRegistryTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.cas_a = SourceCAS(self.root_path / "legion" / "sources.sqlite3")
        self.cas_b = SourceCAS(self.root_path / "daimonmatrix" / "sources.sqlite3")
        self.registry_a = SourceRegistry(self.ledger_a, self.cas_a, clock=lambda: NOW)
        self.registry_b = SourceRegistry(self.ledger_b, self.cas_b, clock=lambda: NOW)
        self.core = source_core()
        self.selector = source_selector(self.core)

    @staticmethod
    def _rehash_bundle(bundle: dict[str, Any]) -> None:
        for item in bundle["items"]:
            item_core = {
                key: item[key] for key in ("blobs", "events", "kind", "series_id")
            }
            item["item_hash"] = b64url(digest("daimon/source-diff-item/v0", item_core))
        bundle["page_hash"] = b64url(
            digest(
                "daimon/source-diff-page/v0",
                {"items": bundle["items"], "page_index": bundle["page_index"]},
            )
        )
        if bundle["continuation"] is not None:
            bundle["continuation"]["page_hash"] = bundle["page_hash"]
            token_body = {
                key: value
                for key, value in bundle["continuation"].items()
                if key not in {"schema", "token_hash"}
            }
            bundle["continuation"]["token_hash"] = b64url(
                digest("daimon/source-continuation/v0", token_body)
            )
        bundle_core = {
            key: value
            for key, value in bundle.items()
            if key not in {"bundle_hash", "schema"}
        }
        bundle["bundle_hash"] = b64url(
            digest("daimon/source-diff-bundle/v0", bundle_core)
        )

    def _claim(
        self,
        registry: SourceRegistry,
        *,
        label: str,
        sequence: int = 0,
        predecessor: dict[str, Any] | None = None,
        action: str = "assert",
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
        ledger = registry.ledger
        evidence_ref: dict[str, Any] | None = None
        manifest_ref: dict[str, Any] | None = None
        payload = {
            "action": action,
            "claim_sequence": sequence,
            "claim_series_id": claim_series_id(
                registry.local_me_id, self.selector["source_id"]
            ),
            "claimant_control_position": {
                "embodiment_id": ledger.local_origin["embodiment_id"],
                "incarnation_id": ledger.local_origin["incarnation_id"],
                "manifest_hash": ledger.authority.manifest.digest,
            },
            "claimant_me_id": registry.local_me_id,
            "evidence_manifest_ref": None,
            "expires_at_ms": NOW + 100_000 if action == "assert" else None,
            "issued_at_ms": NOW,
            "previous_claim_event_hash": (
                None if predecessor is None else predecessor["content_hash"]
            ),
            "previous_claim_event_id": (
                None if predecessor is None else predecessor["event_id"]
            ),
            "relations": ["created-by"],
            "schema": "daimon-source-claim/v0",
            "source_core": self.core,
            "source_id": self.selector["source_id"],
        }
        if action == "assert":
            evidence_ref = registry.cas.put(b"independent corroboration", "text/plain")
            draft = copy.deepcopy(payload)
            draft["evidence_manifest_ref"] = source_content_ref(
                b"placeholder", "application/octet-stream"
            )
            manifest = {
                "claim_binding_hash": source_claim_binding_hash(draft),
                "entries": [
                    {
                        "artifact": None,
                        "assertion": "external-metadata",
                        "content": evidence_ref,
                        "evidence_id": evidence_ref["content_id"],
                        "issuer_me_id": None,
                        "kind": "content",
                        "role": "corroborates",
                    }
                ],
                "schema": "daimon-source-evidence-manifest/v0",
            }
            manifest_ref = registry.cas.put_json(
                manifest,
                "application/vnd.daimon.source-evidence-manifest.v0+json",
            )
            payload["evidence_manifest_ref"] = manifest_ref
        event = registry.append_claim(payload, signer=self.signers[label])
        return event, evidence_ref or {}, manifest_ref

    def test_public_source_mutation_waits_for_exclusive_intake(self) -> None:
        self.registry_b.initialize()
        started = threading.Event()

        def append() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any] | None]:
            started.set()
            return self._claim(self.registry_b, label="daimonmatrix")

        with ThreadPoolExecutor(max_workers=1) as executor:
            with self.registry_b._intake_lock():
                future = executor.submit(append)
                self.assertTrue(started.wait(timeout=1))
                with self.assertRaises(FutureTimeoutError):
                    future.result(timeout=0.1)
            event, _, _ = future.result(timeout=2)
        self.assertEqual(self.ledger_b.event(event["event_id"]), event)

    def _admit(
        self,
        claim: dict[str, Any],
        evidence_ref: dict[str, Any],
        manifest_ref: dict[str, Any],
    ) -> dict[str, Any]:
        cursor = self.registry_a.create_cursor(
            self.selector, signer=self.signers["legion"]
        )["event"]
        policy_ref = self.cas_a.put_json(
            {
                "decision": "admit-exact-evidence",
                "schema": "daimon-source-local-policy/v0",
            },
            "application/vnd.daimon.source-local-policy.v0+json",
        )
        refs = sorted([manifest_ref, evidence_ref], key=canonical_bytes)
        snapshot = {
            "artifact_refs": [],
            "claim_event_ids": [claim["event_id"]],
            "content_refs": refs,
            "contradiction_refs": [],
            "observed_cursor_event_hash": cursor["content_hash"],
            "observed_cursor_event_id": cursor["event_id"],
            "schema": "daimon-source-policy-evidence-snapshot/v0",
            "source_id": self.selector["source_id"],
            "subject": {
                "event_hash": claim["content_hash"],
                "event_id": claim["event_id"],
                "id": claim["payload"]["claim_series_id"],
                "kind": "claim",
            },
        }
        snapshot_ref = self.cas_a.put_json(
            snapshot,
            "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
        )
        payload = {
            "assessment_sequence": 0,
            "assessment_series_id": assessment_series_id(
                self.registry_a.local_me_id,
                claim["payload"]["claim_series_id"],
            ),
            "assessor_me_id": self.registry_a.local_me_id,
            "claim_event_hash": claim["content_hash"],
            "claim_event_id": claim["event_id"],
            "claimant_me_id": self.registry_a.local_me_id,
            "decided_at_ms": NOW,
            "disposition": "admitted",
            "evidence_manifest_ref": manifest_ref,
            "evidence_snapshot_ref": snapshot_ref,
            "policy_ref": policy_ref,
            "previous_assessment_event_id": None,
            "reason_codes": ["admitted:evidence-satisfied"],
            "schema": "daimon-source-assessment/v0",
            "source_id": self.selector["source_id"],
        }
        return self.registry_a.append_assessment(payload, signer=self.signers["legion"])

    def _publish(
        self, claim: dict[str, Any], *, suffix: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        content_ref = self.cas_a.put(
            f"published knowledge {suffix}".encode(), "text/plain"
        )
        original_ref = self.cas_a.put(f"source notes {suffix}".encode(), "text/plain")
        source_uri = f"hmk://dm081/chapters/{suffix}"
        payload = {
            "action": "publish",
            "classification": "public",
            "consent": "explicit",
            "content_ref": content_ref,
            "issued_at_ms": NOW,
            "license": "CC BY-SA 4.0",
            "previous_publication_event_hash": None,
            "previous_publication_event_id": None,
            "provenance_manifest_ref": source_content_ref(
                b"placeholder", "application/octet-stream"
            ),
            "publication_id": publication_id(self.registry_a.local_me_id, source_uri),
            "publication_sequence": 0,
            "publisher_claim_event_id": claim["event_id"],
            "publisher_me_id": self.registry_a.local_me_id,
            "reason": None,
            "schema": "daimon-source-publication/v0",
            "source_id": self.selector["source_id"],
            "source_uri": source_uri,
        }
        original = {
            "authors": [
                {
                    "assertion": "publisher-declared",
                    "evidence_refs": [],
                    "subject_id": "external:dm081-author",
                    "subject_kind": "external",
                }
            ],
            "content_ref": original_ref,
            "kind": "original",
            "node_id": "placeholder",
            "source_uri": f"urn:dm081:source-notes:{suffix}",
        }
        original["node_id"] = provenance_node_id(original)
        output = {
            "authors": copy.deepcopy(original["authors"]),
            "content_ref": content_ref,
            "kind": "derivation",
            "node_id": "placeholder",
            "source_uri": source_uri,
        }
        output["node_id"] = provenance_node_id(output)
        provenance = {
            "edges": [
                {
                    "from_node_id": original["node_id"],
                    "relation": "derived-from",
                    "to_node_id": output["node_id"],
                    "transformation_ref": None,
                }
            ],
            "nodes": sorted([original, output], key=lambda row: str(row["node_id"])),
            "output_node_id": output["node_id"],
            "publication_binding_hash": publication_binding_hash(payload),
            "schema": "daimon-source-provenance-manifest/v0",
        }
        payload["provenance_manifest_ref"] = self.cas_a.put_json(
            provenance,
            "application/vnd.daimon.source-provenance-manifest.v0+json",
        )
        event = self.registry_a.append_publication(
            payload, signer=self.signers["legion"]
        )
        return event, payload

    def test_claim_starts_quarantined_then_exact_local_assessment_admits(self) -> None:
        claim, evidence_ref, manifest_ref = self._claim(self.registry_a, label="legion")
        initial = self.registry_a.status(self.selector)
        self.assertEqual(initial["claims"][0]["intrinsic_state"], "valid-asserted")
        self.assertEqual(initial["claims"][0]["disposition"], "quarantined")
        self.assertEqual(initial["eligible_claimants"], [])

        assert manifest_ref is not None
        self._admit(claim, evidence_ref, manifest_ref)
        admitted = self.registry_a.status(self.selector)
        self.assertEqual(admitted["claims"][0]["disposition"], "admitted")
        self.assertEqual(
            admitted["eligible_claimants"][0]["claimant_me_id"],
            self.registry_a.local_me_id,
        )

    def test_remote_event_without_receiver_cas_remains_incomplete(self) -> None:
        claim, evidence_ref, manifest_ref = self._claim(self.registry_a, label="legion")
        self.ledger_b.ingest([claim], source="compaii@legion")
        remote = self.registry_b.status(self.selector)
        self.assertEqual(remote["claims"][0]["intrinsic_state"], "incomplete")
        self.assertEqual(remote["eligible_claimants"], [])

        assert manifest_ref is not None
        self.cas_b.put(self.cas_a.get(evidence_ref), evidence_ref["media_type"])
        self.cas_b.put(self.cas_a.get(manifest_ref), manifest_ref["media_type"])
        complete = self.registry_b.status(self.selector)
        self.assertEqual(complete["claims"][0]["intrinsic_state"], "valid-asserted")
        self.assertEqual(complete["claims"][0]["disposition"], "quarantined")

    def test_same_claim_position_from_two_embodiments_quarantines_series(self) -> None:
        genesis, _, _ = self._claim(self.registry_a, label="legion")
        self.ledger_b.ingest([genesis], source="compaii@legion")
        successor_a, _, _ = self._claim(
            self.registry_a,
            label="legion",
            sequence=1,
            predecessor=genesis,
            action="retract",
        )
        descendant_a, _, _ = self._claim(
            self.registry_a,
            label="legion",
            sequence=2,
            predecessor=successor_a,
            action="assert",
        )
        successor_b, _, _ = self._claim(
            self.registry_b,
            label="daimonmatrix",
            sequence=1,
            predecessor=genesis,
            action="retract",
        )
        self.ledger_a.ingest([successor_b], source="compaii@daimonmatrix")
        forked = self.registry_a.status(self.selector)
        self.assertEqual(forked["claims"][0]["intrinsic_state"], "forked")
        self.assertEqual(forked["claims"][0]["disposition"], "quarantined")
        self.assertEqual(forked["eligible_claimants"], [])
        self.assertIn(
            descendant_a["event_id"],
            {row["event_id"] for row in self.ledger_a.events()},
        )
        with self.assertRaisesRegex(SourceError, "claim_series_quarantined"):
            self._claim(
                self.registry_a,
                label="legion",
                sequence=3,
                predecessor=descendant_a,
                action="retract",
            )

    def test_assessment_successor_fork_excludes_locally_admitted_claim(self) -> None:
        claim, evidence_ref, manifest_ref = self._claim(self.registry_a, label="legion")
        assert manifest_ref is not None
        admitted = self._admit(claim, evidence_ref, manifest_ref)
        self.ledger_b.ingest(self.ledger_a.events(), source="compaii@legion")
        peer = SourceRegistry(self.ledger_b, self.cas_a, clock=lambda: NOW)
        first = {
            **copy.deepcopy(admitted["payload"]),
            "assessment_sequence": 1,
            "decided_at_ms": NOW + 1,
            "disposition": "quarantined",
            "previous_assessment_event_id": admitted["event_id"],
            "reason_codes": ["quarantined:contradiction"],
        }
        self.registry_a.append_assessment(first, signer=self.signers["legion"])
        second = {
            **copy.deepcopy(first),
            "decided_at_ms": NOW + 2,
            "disposition": "rejected",
            "reason_codes": ["rejected:policy"],
        }
        competing = peer.append_assessment(second, signer=self.signers["daimonmatrix"])
        self.ledger_a.ingest([competing], source="compaii@daimonmatrix")
        status = self.registry_a.status(self.selector)
        self.assertEqual(status["claims"][0]["disposition"], "quarantined")
        self.assertEqual(status["eligible_claimants"], [])
        self.assertIn(
            "quarantined:assessment-fork", status["claims"][0]["reason_codes"]
        )

    def test_publication_successor_fork_is_retained_and_never_offered(self) -> None:
        claim, _, _ = self._claim(self.registry_a, label="legion")
        published, payload = self._publish(claim, suffix="publication-fork")
        self.ledger_b.ingest(self.ledger_a.events(), source="compaii@legion")
        peer = SourceRegistry(self.ledger_b, self.cas_a, clock=lambda: NOW)
        tombstone = {
            **copy.deepcopy(payload),
            "action": "tombstone",
            "classification": None,
            "consent": None,
            "content_ref": None,
            "issued_at_ms": NOW + 1,
            "license": None,
            "previous_publication_event_hash": published["content_hash"],
            "previous_publication_event_id": published["event_id"],
            "provenance_manifest_ref": None,
            "publication_sequence": 1,
            "reason": "first withdrawal",
        }
        self.registry_a.append_publication(tombstone, signer=self.signers["legion"])
        competing_payload = {
            **copy.deepcopy(tombstone),
            "issued_at_ms": NOW + 2,
            "reason": "competing withdrawal",
        }
        competing = peer.append_publication(
            competing_payload, signer=self.signers["daimonmatrix"]
        )
        self.ledger_a.ingest([competing], source="compaii@daimonmatrix")
        status = self.registry_a.status(self.selector)
        self.assertEqual(status["publications"][0]["state"], "forked")

        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000009",
            requester_me_id=self.registry_a.local_me_id,
            requester_cursor={
                "observer_me_id": self.registry_a.local_me_id,
                "schema": "dm.source-empty-cursor/v0",
                "source_id": self.selector["source_id"],
            },
            max_items=8,
            max_bytes=4_194_304,
        )
        self.assertNotIn(
            payload["publication_id"], {item["series_id"] for item in bundle["items"]}
        )

    def test_reviewed_publication_tombstones_without_deleting_history(self) -> None:
        claim, _, _ = self._claim(self.registry_a, label="legion")
        content_ref = self.cas_a.put(b"published knowledge", "text/plain")
        original_ref = self.cas_a.put(b"source notes", "text/plain")
        source_uri = "hmk://dm081/chapters/registry-flow"
        draft = {
            "action": "publish",
            "classification": "public",
            "consent": "explicit",
            "content_ref": content_ref,
            "issued_at_ms": NOW,
            "license": "CC BY-SA 4.0",
            "previous_publication_event_hash": None,
            "previous_publication_event_id": None,
            "provenance_manifest_ref": source_content_ref(
                b"placeholder", "application/octet-stream"
            ),
            "publication_id": publication_id(self.registry_a.local_me_id, source_uri),
            "publication_sequence": 0,
            "publisher_claim_event_id": claim["event_id"],
            "publisher_me_id": self.registry_a.local_me_id,
            "reason": None,
            "schema": "daimon-source-publication/v0",
            "source_id": self.selector["source_id"],
            "source_uri": source_uri,
        }
        original = {
            "authors": [
                {
                    "assertion": "publisher-declared",
                    "evidence_refs": [],
                    "subject_id": "external:dm081-author",
                    "subject_kind": "external",
                }
            ],
            "content_ref": original_ref,
            "kind": "original",
            "node_id": "placeholder",
            "source_uri": "urn:dm081:source-notes",
        }
        original["node_id"] = provenance_node_id(original)
        output = {
            "authors": copy.deepcopy(original["authors"]),
            "content_ref": content_ref,
            "kind": "derivation",
            "node_id": "placeholder",
            "source_uri": source_uri,
        }
        output["node_id"] = provenance_node_id(output)
        provenance = {
            "edges": [
                {
                    "from_node_id": original["node_id"],
                    "relation": "derived-from",
                    "to_node_id": output["node_id"],
                    "transformation_ref": None,
                }
            ],
            "nodes": sorted([original, output], key=lambda row: str(row["node_id"])),
            "output_node_id": output["node_id"],
            "publication_binding_hash": publication_binding_hash(draft),
            "schema": "daimon-source-provenance-manifest/v0",
        }
        provenance_ref = self.cas_a.put_json(
            provenance,
            "application/vnd.daimon.source-provenance-manifest.v0+json",
        )
        draft["provenance_manifest_ref"] = provenance_ref
        published = self.registry_a.append_publication(
            draft, signer=self.signers["legion"]
        )
        self.assertEqual(
            self.registry_a.status(self.selector)["publications"][0]["state"],
            "published",
        )

        tombstone = {
            **draft,
            "action": "tombstone",
            "classification": None,
            "consent": None,
            "content_ref": None,
            "issued_at_ms": NOW + 1,
            "license": None,
            "previous_publication_event_hash": published["content_hash"],
            "previous_publication_event_id": published["event_id"],
            "provenance_manifest_ref": None,
            "publication_sequence": 1,
            "reason": "withdrawn by publisher",
        }
        self.registry_a.append_publication(tombstone, signer=self.signers["legion"])
        self.assertEqual(
            self.registry_a.status(self.selector)["publications"][0]["state"],
            "tombstoned",
        )
        self.assertEqual(self.cas_a.get(content_ref), b"published knowledge")

    def test_diff_and_incoming_are_content_bound_and_preview_has_no_writes(
        self,
    ) -> None:
        self.registry_b.initialize()
        receiver_cursor = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        requester_cursor = self.registry_b.cursor_envelope(receiver_cursor)
        self._claim(self.registry_a, label="legion")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000001",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=requester_cursor,
            max_items=8,
            max_bytes=1_048_576,
        )
        self.assertEqual(len(bundle["items"]), 1)
        self.assertEqual(bundle["items"][0]["kind"], "claim")

        ledger_before = self.ledger_b.path.read_bytes()
        cas_before = self.cas_b.path.read_bytes()
        preview = self.registry_b.incoming(bundle)
        self.assertEqual(preview["results"][0]["outcome"], "admissible-claim-candidate")
        self.assertEqual(self.ledger_b.path.read_bytes(), ledger_before)
        self.assertEqual(self.cas_b.path.read_bytes(), cas_before)

        tampered = copy.deepcopy(bundle)
        tampered["items"][0]["blobs"][0]["data"] = b64url(b"tampered")
        with self.assertRaisesRegex(SourceError, "source_diff_item_hash_mismatch"):
            self.registry_b.incoming(tampered)

        kind_substitution = copy.deepcopy(bundle)
        item = kind_substitution["items"][0]
        item["kind"] = "publication"
        item["item_hash"] = b64url(
            digest(
                "daimon/source-diff-item/v0",
                {
                    "blobs": item["blobs"],
                    "events": item["events"],
                    "kind": item["kind"],
                    "series_id": item["series_id"],
                },
            )
        )
        kind_substitution["page_hash"] = b64url(
            digest(
                "daimon/source-diff-page/v0",
                {
                    "items": kind_substitution["items"],
                    "page_index": kind_substitution["page_index"],
                },
            )
        )
        bundle_core = {
            key: value
            for key, value in kind_substitution.items()
            if key not in {"bundle_hash", "schema"}
        }
        kind_substitution["bundle_hash"] = b64url(
            digest("daimon/source-diff-bundle/v0", bundle_core)
        )
        with self.assertRaisesRegex(SourceError, "invalid_source_diff_item"):
            self.registry_b.incoming(kind_substitution)

        self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )
        with self.assertRaisesRegex(SourceError, "source_incoming_cursor_stale"):
            self.registry_b.incoming(bundle)

    def test_pull_resumes_after_crash_and_never_promotes(self) -> None:
        self.registry_b.initialize()
        receiver_cursor = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        requester_cursor = self.registry_b.cursor_envelope(receiver_cursor)
        self._claim(self.registry_a, label="legion")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000002",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=requester_cursor,
            max_items=8,
            max_bytes=1_048_576,
        )
        preview = self.registry_b.incoming(bundle)
        operation_id = "30000000-0000-4000-8000-000000000001"
        with self.assertRaisesRegex(SourceError, "source_pull_fault_injected"):
            self.registry_b.pull(
                operation_id=operation_id,
                bundle=bundle,
                preview=preview,
                signer=self.signers["daimonmatrix"],
                _fault_after_stage="blobs",
            )
        self.assertFalse(
            any(event["kind"] == CLAIM_EVENT_KIND for event in self.ledger_b.events())
        )

        result = self.registry_b.pull(
            operation_id=operation_id,
            bundle=bundle,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        replay = self.registry_b.pull(
            operation_id=operation_id,
            bundle=bundle,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(replay, result)
        self.assertEqual(result["decision_event_ids"], [])
        self.assertEqual(result["outcomes"][0]["outcome"], "admitted-to-quarantine")
        self.assertEqual(
            sum(event["kind"] == CLAIM_EVENT_KIND for event in self.ledger_b.events()),
            1,
        )
        status = self.registry_b.status(self.selector)
        self.assertEqual(status["claims"][0]["disposition"], "quarantined")
        self.assertEqual(status["eligible_claimants"], [])

    def test_item_with_transitive_publication_creates_every_import_receipt(
        self,
    ) -> None:
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        claim, _, _ = self._claim(self.registry_a, label="legion")
        first, first_payload = self._publish(claim, suffix="transitive-first")
        second, second_payload = self._publish(claim, suffix="transitive-second")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])

        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000010",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=self.registry_b.cursor_envelope(starting),
            max_items=8,
            max_bytes=4_194_304,
        )
        transitive_item = next(
            item
            for item in bundle["items"]
            if {
                event["payload"]["publication_id"]
                for event in item["events"]
                if event["kind"] == "matrix/source-publication"
            }
            == {first_payload["publication_id"], second_payload["publication_id"]}
        )
        bundle["items"] = [transitive_item]
        self._rehash_bundle(bundle)
        preview = self.registry_b.incoming(bundle)
        self.assertEqual(
            preview["results"][0]["outcome"],
            "admissible-publication-candidate",
        )
        result = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000010",
            bundle=bundle,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(len(result["decision_event_ids"]), 2)
        decisions = [
            self.ledger_b.event(event_id) for event_id in result["decision_event_ids"]
        ]
        self.assertNotIn(None, decisions)
        self.assertEqual(
            {decision["payload"]["publication_id"] for decision in decisions},  # type: ignore[index]
            {first_payload["publication_id"], second_payload["publication_id"]},
        )
        self.assertEqual(
            {claim["event_id"], first["event_id"], second["event_id"]},
            set(result["accepted_event_ids"]),
        )

    def test_incomplete_item_is_reported_but_not_landed_or_marked_known(self) -> None:
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        claim, evidence_ref, _ = self._claim(self.registry_a, label="legion")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        complete = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000011",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=self.registry_b.cursor_envelope(starting),
            max_items=8,
            max_bytes=4_194_304,
        )
        incomplete = copy.deepcopy(complete)
        incomplete["items"][0]["blobs"] = [
            blob
            for blob in incomplete["items"][0]["blobs"]
            if blob["reference"]["content_id"] != evidence_ref["content_id"]
        ]
        self._rehash_bundle(incomplete)
        preview = self.registry_b.incoming(incomplete)
        self.assertEqual(preview["results"][0]["outcome"], "incomplete")
        self.assertEqual(
            preview["results"][0]["missing_references"],
            [evidence_ref["content_id"]],
        )
        result = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000011",
            bundle=incomplete,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(result["accepted_event_ids"], [])
        self.assertEqual(result["outcomes"][0]["outcome"], "incomplete")
        self.assertEqual(self.registry_b.status(self.selector)["claims"], [])
        self.assertIsNone(self.ledger_b.event(claim["event_id"]))

        achieved = self.registry_b.latest_cursor(self.selector)
        assert achieved is not None
        retry = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000012",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=achieved,
            max_items=8,
            max_bytes=4_194_304,
        )
        retry_preview = self.registry_b.incoming(retry)
        self.assertEqual(
            retry_preview["results"][0]["outcome"],
            "admissible-claim-candidate",
        )

    def test_paginated_pull_keeps_starting_cursor_until_terminal_page(self) -> None:
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        requester_cursor = self.registry_b.cursor_envelope(starting)
        claim, _, _ = self._claim(self.registry_a, label="legion")
        self._publish(claim, suffix="pagination")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])

        first = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000004",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=requester_cursor,
            max_items=1,
            max_bytes=4_194_304,
        )
        self.assertIsNotNone(first["continuation"])
        first_preview = self.registry_b.incoming(first)
        first_pull = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000004",
            bundle=first,
            preview=first_preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(first_pull["achieved_cursor_hash"], starting["content_hash"])
        self.assertEqual(first_pull["outcomes"][0]["outcome"], "admitted-to-quarantine")

        second = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000004",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=requester_cursor,
            max_items=1,
            max_bytes=4_194_304,
            continuation=first["continuation"],
        )
        self.assertEqual(second["page_index"], 1)
        self.assertEqual(second["previous_page_hash"], first["page_hash"])
        self.assertIsNone(second["continuation"])
        second_preview = self.registry_b.incoming(second)
        second_pull = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000005",
            bundle=second,
            preview=second_preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertNotEqual(
            second_pull["achieved_cursor_hash"], starting["content_hash"]
        )
        self.assertEqual(len(second_pull["decision_event_ids"]), 1)
        self.assertEqual(
            {
                row["kind"]
                for row in [*first_preview["results"], *second_preview["results"]]
            },
            {"claim", "publication"},
        )

        replay = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000004",
            bundle=first,
            preview=first_preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(replay, first_pull)

    def test_malformed_item_is_rejected_while_complete_prefix_lands(self) -> None:
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        claim, _, _ = self._claim(self.registry_a, label="legion")
        self._publish(claim, suffix="partial-prefix")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000005",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=self.registry_b.cursor_envelope(starting),
            max_items=8,
            max_bytes=4_194_304,
        )
        malformed = copy.deepcopy(bundle)
        publication_item = next(
            item for item in malformed["items"] if item["kind"] == "publication"
        )
        publication_event = next(
            event
            for event in publication_item["events"]
            if event["kind"] == "matrix/source-publication"
        )
        publication_event["signature"]["value"] = "A" * 86
        item_core = {
            key: publication_item[key]
            for key in ("blobs", "events", "kind", "series_id")
        }
        publication_item["item_hash"] = b64url(
            digest("daimon/source-diff-item/v0", item_core)
        )
        malformed["page_hash"] = b64url(
            digest(
                "daimon/source-diff-page/v0",
                {"items": malformed["items"], "page_index": malformed["page_index"]},
            )
        )
        bundle_core = {
            key: malformed[key]
            for key in malformed
            if key not in {"bundle_hash", "schema"}
        }
        malformed["bundle_hash"] = b64url(
            digest("daimon/source-diff-bundle/v0", bundle_core)
        )

        preview = self.registry_b.incoming(malformed)
        outcomes = {row["kind"]: row["outcome"] for row in preview["results"]}
        self.assertEqual(outcomes["claim"], "admissible-claim-candidate")
        self.assertEqual(outcomes["publication"], "rejected")
        result = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000006",
            bundle=malformed,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(result["decision_event_ids"], [])
        status = self.registry_b.status(self.selector)
        self.assertEqual(len(status["claims"]), 1)
        self.assertEqual(status["publications"], [])

    def test_publication_pull_quarantines_then_separate_promotion_preserves_authors(
        self,
    ) -> None:
        contract = runtime_contract_validator()
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        contract.validate(self.selector)
        contract.validate(self.registry_b.cursor_envelope(starting))
        claim, evidence_ref, manifest_ref = self._claim(self.registry_a, label="legion")
        publication, publication_payload = self._publish(claim, suffix="pull-promote")
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000003",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=self.registry_b.cursor_envelope(starting),
            max_items=8,
            max_bytes=4_194_304,
        )
        contract.validate(bundle)
        preview = self.registry_b.incoming(bundle)
        contract.validate(preview)
        pull = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000002",
            bundle=bundle,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        contract.validate(pull)
        self.assertEqual(len(pull["decision_event_ids"]), 1)
        self.assertEqual(
            {row["outcome"] for row in pull["outcomes"]},
            {"admitted-to-quarantine"},
        )
        initial_decision = self.ledger_b.event(pull["decision_event_ids"][0])
        assert initial_decision is not None
        self.assertEqual(initial_decision["payload"]["decision"], "quarantined")
        self.assertIsNone(initial_decision["payload"]["target_memory_category"])

        achieved = next(
            event
            for event in self.ledger_b.events()
            if event["content_hash"] == pull["achieved_cursor_hash"]
        )
        assessment_policy_ref = self.cas_b.put_json(
            {
                "decision": "admit-exact-evidence",
                "schema": "daimon-source-local-policy/v0",
            },
            "application/vnd.daimon.source-local-policy.v0+json",
        )
        assessment_snapshot = {
            "artifact_refs": [],
            "claim_event_ids": [claim["event_id"]],
            "content_refs": sorted([evidence_ref, manifest_ref], key=canonical_bytes),
            "contradiction_refs": [],
            "observed_cursor_event_hash": achieved["content_hash"],
            "observed_cursor_event_id": achieved["event_id"],
            "schema": "daimon-source-policy-evidence-snapshot/v0",
            "source_id": self.selector["source_id"],
            "subject": {
                "event_hash": claim["content_hash"],
                "event_id": claim["event_id"],
                "id": claim["payload"]["claim_series_id"],
                "kind": "claim",
            },
        }
        assessment_snapshot_ref = self.cas_b.put_json(
            assessment_snapshot,
            "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
        )
        self.registry_b.append_assessment(
            {
                "assessment_sequence": 0,
                "assessment_series_id": assessment_series_id(
                    self.registry_b.local_me_id,
                    claim["payload"]["claim_series_id"],
                ),
                "assessor_me_id": self.registry_b.local_me_id,
                "claim_event_hash": claim["content_hash"],
                "claim_event_id": claim["event_id"],
                "claimant_me_id": claim["payload"]["claimant_me_id"],
                "decided_at_ms": NOW + 1,
                "disposition": "admitted",
                "evidence_manifest_ref": manifest_ref,
                "evidence_snapshot_ref": assessment_snapshot_ref,
                "policy_ref": assessment_policy_ref,
                "previous_assessment_event_id": None,
                "reason_codes": ["admitted:evidence-satisfied"],
                "schema": "daimon-source-assessment/v0",
                "source_id": self.selector["source_id"],
            },
            signer=self.signers["daimonmatrix"],
        )
        promotion_policy = {
            "classification": publication_payload["classification"],
            "consent": publication_payload["consent"],
            "content_ref": publication_payload["content_ref"],
            "content_safety_passed": True,
            "final_render_reviewed": True,
            "license": publication_payload["license"],
            "provenance_manifest_ref": publication_payload["provenance_manifest_ref"],
            "publication_event_hash": publication["content_hash"],
            "publication_event_id": publication["event_id"],
            "publication_id": publication_payload["publication_id"],
            "schema": "daimon-source-promotion-policy/v0",
            "target_memory_category": "external-reference",
        }
        promotion_policy_ref = self.cas_b.put_json(
            promotion_policy,
            "application/vnd.daimon.source-promotion-policy.v0+json",
        )
        promotion_snapshot = {
            "artifact_refs": [],
            "claim_event_ids": [claim["event_id"]],
            "content_refs": sorted(
                [
                    publication_payload["content_ref"],
                    publication_payload["provenance_manifest_ref"],
                ],
                key=canonical_bytes,
            ),
            "contradiction_refs": [],
            "observed_cursor_event_hash": achieved["content_hash"],
            "observed_cursor_event_id": achieved["event_id"],
            "schema": "daimon-source-policy-evidence-snapshot/v0",
            "source_id": self.selector["source_id"],
            "subject": {
                "event_hash": publication["content_hash"],
                "event_id": publication["event_id"],
                "id": publication_payload["publication_id"],
                "kind": "publication",
            },
        }
        promotion_snapshot_ref = self.cas_b.put_json(
            promotion_snapshot,
            "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
        )
        capability = create_capability(
            hashlib.sha256(b"dm081-source-service").digest(),
            client_id="client:dm081-source",
            methods=sorted(SOURCE_METHODS),
            not_before_ms=NOW - 1,
            not_after_ms=NOW + 1,
        )
        service = HostedWeave(
            self.ledger_b,
            self.signers["daimonmatrix"],
            {capability.capability_id: capability},
            lambda: NOW,
            sources=SourceServiceContext(self.registry_b),
        )
        request = create_request(
            capability,
            request_id="31000000-0000-4000-8000-000000000001",
            issued_at_ms=NOW,
            method="source.promote",
            params={
                "evidence_snapshot_ref": promotion_snapshot_ref,
                "policy_ref": promotion_policy_ref,
                "publication_id": publication_payload["publication_id"],
            },
            nonce=b"p" * 16,
        )
        first_response = service.handle(request)
        replay_response = service.handle(request)
        self.assertEqual(first_response, replay_response)
        self.assertTrue(first_response["ok"], first_response)
        promoted = first_response["result"]
        self.assertNotEqual(
            promoted["decision"]["event_id"], initial_decision["event_id"]
        )
        self.assertEqual(promoted["decision"]["payload"]["decision_sequence"], 1)
        projection = promoted["projection"]
        contract.validate(self.registry_b.status(self.selector))
        contract.validate(projection)
        self.assertTrue(projection["active"])
        self.assertEqual(projection["target_memory_category"], "external-reference")
        self.assertEqual(
            projection["authors"][0]["authors"][0]["subject_id"],
            "external:dm081-author",
        )

    def test_republish_after_tombstone_creates_new_quarantine_successor(self) -> None:
        self.registry_b.initialize()
        self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )
        claim, _, _ = self._claim(self.registry_a, label="legion")
        publication, payload = self._publish(claim, suffix="republish")

        def exchange(label: str) -> dict[str, Any]:
            self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
            receiver = self.registry_b.latest_cursor(self.selector)
            assert receiver is not None
            bundle = self.registry_a.diff(
                selector=self.selector,
                request_event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"dm081:{label}")),
                requester_me_id=self.registry_b.local_me_id,
                requester_cursor=receiver,
                max_items=8,
                max_bytes=4_194_304,
            )
            preview = self.registry_b.incoming(bundle)
            return self.registry_b.pull(
                operation_id=str(uuid.uuid5(uuid.NAMESPACE_OID, f"dm081:{label}:pull")),
                bundle=bundle,
                preview=preview,
                signer=self.signers["daimonmatrix"],
            )

        first = exchange("initial")
        first_decision = self.ledger_b.event(first["decision_event_ids"][0])
        assert first_decision is not None

        tombstone_payload = {
            **copy.deepcopy(payload),
            "action": "tombstone",
            "classification": None,
            "consent": None,
            "content_ref": None,
            "issued_at_ms": NOW + 1,
            "license": None,
            "previous_publication_event_hash": publication["content_hash"],
            "previous_publication_event_id": publication["event_id"],
            "provenance_manifest_ref": None,
            "publication_sequence": 1,
            "reason": "withdrawn for revision",
        }
        tombstone = self.registry_a.append_publication(
            tombstone_payload, signer=self.signers["legion"]
        )
        exchange("tombstone")

        republished_payload = {
            **copy.deepcopy(payload),
            "issued_at_ms": NOW + 2,
            "previous_publication_event_hash": tombstone["content_hash"],
            "previous_publication_event_id": tombstone["event_id"],
            "publication_sequence": 2,
            "provenance_manifest_ref": source_content_ref(
                b"placeholder", "application/octet-stream"
            ),
        }
        provenance = self.cas_a.get_json(payload["provenance_manifest_ref"])
        provenance["publication_binding_hash"] = publication_binding_hash(
            republished_payload
        )
        republished_payload["provenance_manifest_ref"] = self.cas_a.put_json(
            provenance,
            "application/vnd.daimon.source-provenance-manifest.v0+json",
        )
        republished = self.registry_a.append_publication(
            republished_payload, signer=self.signers["legion"]
        )
        result = exchange("republished")
        self.assertEqual(len(result["decision_event_ids"]), 1)
        successor = self.ledger_b.event(result["decision_event_ids"][0])
        assert successor is not None
        self.assertEqual(successor["payload"]["decision"], "quarantined")
        self.assertEqual(successor["payload"]["decision_sequence"], 1)
        self.assertEqual(
            successor["payload"]["previous_decision_event_id"],
            first_decision["event_id"],
        )
        self.assertEqual(
            successor["payload"]["publication_event_id"], republished["event_id"]
        )

    def test_fresh_receiver_lands_tombstone_without_withdrawn_content(self) -> None:
        self.registry_b.initialize()
        starting = self.registry_b.create_cursor(
            self.selector, signer=self.signers["daimonmatrix"]
        )["event"]
        claim, _, _ = self._claim(self.registry_a, label="legion")
        publication, payload = self._publish(claim, suffix="fresh-tombstone")
        provenance = self.cas_a.get_json(payload["provenance_manifest_ref"])
        withdrawn_references = [
            payload["content_ref"],
            payload["provenance_manifest_ref"],
            *(node["content_ref"] for node in provenance["nodes"]),
            *(
                edge["transformation_ref"]
                for edge in provenance["edges"]
                if edge["transformation_ref"] is not None
            ),
        ]
        withdrawn_refs = {reference["content_id"] for reference in withdrawn_references}
        tombstone_payload = {
            **copy.deepcopy(payload),
            "action": "tombstone",
            "classification": None,
            "consent": None,
            "content_ref": None,
            "issued_at_ms": NOW + 1,
            "license": None,
            "previous_publication_event_hash": publication["content_hash"],
            "previous_publication_event_id": publication["event_id"],
            "provenance_manifest_ref": None,
            "publication_sequence": 1,
            "reason": "withdrawn before first exchange",
        }
        tombstone = self.registry_a.append_publication(
            tombstone_payload, signer=self.signers["legion"]
        )
        self.registry_a.create_cursor(self.selector, signer=self.signers["legion"])
        bundle = self.registry_a.diff(
            selector=self.selector,
            request_event_id="20000000-0000-4000-8000-000000000013",
            requester_me_id=self.registry_b.local_me_id,
            requester_cursor=self.registry_b.cursor_envelope(starting),
            max_items=8,
            max_bytes=4_194_304,
        )
        publication_item = next(
            item for item in bundle["items"] if item["kind"] == "publication"
        )
        offered_refs = {
            blob["reference"]["content_id"] for blob in publication_item["blobs"]
        }
        self.assertTrue(withdrawn_refs.isdisjoint(offered_refs))
        preview = self.registry_b.incoming(bundle)
        self.assertNotIn("incomplete", {row["outcome"] for row in preview["results"]})
        result = self.registry_b.pull(
            operation_id="30000000-0000-4000-8000-000000000013",
            bundle=bundle,
            preview=preview,
            signer=self.signers["daimonmatrix"],
        )
        self.assertEqual(result["decision_event_ids"], [])
        self.assertEqual(
            self.registry_b.status(self.selector)["publications"][0]["state"],
            "tombstoned",
        )
        self.assertEqual(self.ledger_b.event(tombstone["event_id"]), tombstone)
        for reference in withdrawn_references:
            self.assertFalse(self.cas_b.has(reference))


class SyntheticSourceJourneyTests(unittest.TestCase):
    def test_two_being_report_is_closed_reproducible_and_secret_free(self) -> None:
        reports: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="dm081-synthetic-") as temporary:
            parent = Path(temporary)
            for label in ("a", "b"):
                reports.append(run_synthetic_sources(parent / label))
        self.assertEqual(canonical_bytes(reports[0]), canonical_bytes(reports[1]))
        self.assertNotEqual(
            reports[0]["publisher_being_ref"], reports[0]["receiver_being_ref"]
        )
        raw = canonical_bytes(reports[0])
        for forbidden in (b"private", b"seed", b"password", b"/tmp/", b"localhost"):
            self.assertNotIn(forbidden, raw)
        schema = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "schemas/source/v0/synthetic.schema.json"
            ).read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(reports[0])

    def test_synthetic_entrypoint_emits_exact_report_and_rejects_nonempty_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="dm081-entrypoint-") as temporary:
            parent = Path(temporary)
            state_root = parent / "state"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.synthetic_sources",
                    "--state-root",
                    str(state_root),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                env={**os.environ, "PYTHONPATH": "src"},
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(
                process.stdout,
                (
                    ROOT / "conformance/fixtures/dm081-synthetic-source.json"
                ).read_bytes(),
            )
            report = json.loads(process.stdout)
            self.assertEqual(report["schema"], "dm.synthetic-source-report/v0")
            replay = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "daimon_matrix.synthetic_sources",
                    "--state-root",
                    str(state_root),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                env={**os.environ, "PYTHONPATH": "src"},
            )
            self.assertEqual(replay.returncode, 1)
            self.assertIn(b"synthetic_source_root_not_empty", replay.stderr)


class SourcePublishedEvidenceTests(unittest.TestCase):
    def test_vectors_fixture_and_generator_are_byte_exact(self) -> None:
        outputs = generate_dm081_vectors()
        for path, expected in outputs.items():
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file(), path)
                self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(
            (ROOT / "conformance/fixtures/dm081-synthetic-source.json").read_bytes(),
            (ROOT / "vectors/source/v0/valid/report.json").read_bytes(),
        )
        index = json.loads((ROOT / "vectors/source/v0/index.json").read_bytes())
        self.assertEqual(index["schema"], "dm.source-vector-index/v0")
        for entry in index["entries"]:
            raw = (ROOT / "vectors/source/v0" / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])

    def test_section14_registry_is_exact_closed_and_executable(self) -> None:
        registry = json.loads(
            (ROOT / "conformance/source-v0-section14.json").read_bytes()
        )
        schema = json.loads(
            (ROOT / "schemas/source/v0/scenarios.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(registry)
        spec = (ROOT / "specs/source-ancestry.md").read_text(encoding="utf-8")
        section = spec.split("## 14. Required positive and negative scenarios", 1)[
            1
        ].split("## 15. Cross-protocol and downstream contracts", 1)[0]
        expected = []
        for line in section.splitlines():
            if not line.startswith("|") or line.startswith("|---"):
                continue
            columns = [column.strip() for column in line.strip().strip("|").split("|")]
            if columns != ["Scenario", "Required result"]:
                expected.append(columns)
        self.assertEqual(registry["row_count"], len(expected))
        self.assertEqual(
            [[row["scenario"], row["required_result"]] for row in registry["rows"]],
            expected,
        )
        self.assertEqual(
            [row["index"] for row in registry["rows"]],
            list(range(1, len(expected) + 1)),
        )
        for row in registry["rows"]:
            self.assertEqual(row["evidence"], sorted(set(row["evidence"])))
            for test_id in row["evidence"]:
                _test_exists(test_id, ROOT)

    def test_every_valid_runtime_vector_matches_its_public_schema(self) -> None:
        runtime = runtime_contract_validator()
        source_contract = json.loads(
            (ROOT / "schemas/source/v0/contracts.schema.json").read_bytes()
        )
        event_schema = json.loads(
            (ROOT / "schemas/weave/v1/event.schema.json").read_bytes()
        )
        schemas = [source_contract, runtime.schema, event_schema]
        resources = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas
        )
        event_validator = Draft202012Validator(
            event_schema, registry=resources, format_checker=FormatChecker()
        )
        synthetic_schema = json.loads(
            (ROOT / "schemas/source/v0/synthetic.schema.json").read_bytes()
        )
        for path in sorted((ROOT / "vectors/source/v0/valid").glob("*.json")):
            value = json.loads(path.read_bytes())
            with self.subTest(path=path.name):
                if path.name == "report.json":
                    Draft202012Validator(synthetic_schema).validate(value)
                elif value.get("protocol") == "dm.we.v1":
                    event_validator.validate(value)
                else:
                    runtime.validate(value)


class HostedSourceRuntimeTests(RuntimeFixture):
    def test_v7_bundle_loads_source_runtime_and_authenticated_status(self) -> None:
        state_root, bundle, capability = self.make_bundle(state_name="sources-v7")
        bundle.update(
            {
                "authority_history": [],
                "peer_transport": None,
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
                / "schemas/hosted/v7/bundle.schema.json"
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
        selector = source_selector(source_core())
        request = create_request(
            capability,
            request_id="40000000-0000-4000-8000-000000000001",
            issued_at_ms=NOW,
            method="source.status",
            params={"selector": selector},
            nonce=b"s" * 16,
        )
        response = runtime.service.handle(request)
        self.assertTrue(response["ok"], response)
        self.assertEqual(response["result"]["selector"], selector)
        self.assertEqual(response["result"]["claims"], [])

        collision = copy.deepcopy(bundle)
        collision["sources"]["cas_filename"] = collision["ledger"]
        bundle_path.write_bytes(canonical_bytes(collision))
        with self.assertRaisesRegex(HostedRuntimeError, "runtime_filename_collision"):
            load_runtime(
                state_root,
                "runtime.json",
                lambda: bytearray(PASSWORD),
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
