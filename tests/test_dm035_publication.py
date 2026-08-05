from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import multiprocessing
import os
import subprocess
import sys
import threading
import unittest
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any, ClassVar, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

import daimon_matrix.publication as publication
from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.publication import (
    COMPAII_STATE_COMMIT,
    PROVIDER_ADAPTER_ID,
    PROVIDER_POLICY_HASH,
    PublicationCoordinator,
    PublicationError,
    PublicationJournal,
    create_content_ref,
    create_publication_policy,
    create_publication_profile,
    create_publication_request,
    reviewer_descriptor,
    sign_publication_review,
    validate_publication_acceptance,
    validate_publication_claim,
    validate_publication_policy,
    validate_publication_profile,
)
from daimon_matrix.weave import EVENT_KINDS, verify_event
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "vectors" / "publication" / "v1"
SCHEMA_PATH = ROOT / "schemas" / "publication" / "v1" / "contracts.schema.json"
DEFAULT_PROVIDER_ROOT = ROOT.parent / "compaii-state"
DEFAULT_HMK_ROOT = ROOT.parent / "hermes-memory-kit"


class MutableClock:
    def __init__(self, value: int = NOW) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class Crash(BaseException):
    pass


def hold_publication_journal(path: str, ready: Any, release: Any) -> None:
    journal = PublicationJournal(Path(path))
    journal.initialize()
    with journal.exclusive():
        ready.set()
        release.wait(10)


def load_provider(root: Path) -> ModuleType:
    name = "dm035_compaii_state_provider"
    spec = importlib.util.spec_from_file_location(name, root / "matrix_publisher.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("provider module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(root))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(root))
    return module


class RealProviderTransport:
    def __init__(self, module: ModuleType, api: Any) -> None:
        self.module = module
        self.api = api
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lose_after_apply = False
        self.manifest_override: Mapping[str, Any] | None = None
        self.corrupt_apply = False
        self.apply_entered: threading.Event | None = None
        self.apply_release: threading.Event | None = None
        self._lock = threading.Lock()

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        with self._lock:
            self.calls.append((operation, copy.deepcopy(dict(document))))
        if operation == "manifest":
            return cast(
                Mapping[str, Any],
                self.module.manifest()
                if self.manifest_override is None
                else self.manifest_override,
            )
        if operation == "plan":
            return cast(Mapping[str, Any], self.api.plan(document["request"]))
        if operation == "acquire":
            return cast(Mapping[str, Any], self.api.acquire_lease(**document))
        if operation == "apply":
            if self.apply_entered is not None and self.apply_release is not None:
                self.apply_entered.set()
                if not self.apply_release.wait(5):
                    raise TimeoutError("synthetic blocked apply timed out")
            result = self.api.apply(document["plan"], document["lease"])
            if self.lose_after_apply:
                self.lose_after_apply = False
                raise ConnectionError("synthetic provider response loss")
            if self.corrupt_apply:
                self.corrupt_apply = False
                result = copy.deepcopy(result)
                result["artifact_sha256"] = "0" * 64
            return cast(Mapping[str, Any], result)
        if operation == "reconcile":
            return cast(Mapping[str, Any], self.api.reconcile(document["receipt"]))
        if operation == "release":
            return cast(Mapping[str, Any], self.api.release_lease(document["lease"]))
        raise RuntimeError("unexpected test operation")


def provider_id(kind: str, value: Mapping[str, Any]) -> str:
    return f"dm:publisher-{kind}:v1:" + b64url(
        hashlib.sha256(
            f"dm/publisher/{kind}/v1\x00".encode() + canonical_bytes(value)
        ).digest()
    )


class ModelPublisherTransport:
    """Credential-free closed provider model for public Matrix conformance."""

    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock
        self.generation = 0
        self.receipts: dict[str, dict[str, Any]] = {}
        self.receipt_by_plan: dict[str, dict[str, Any]] = {}
        self.effect_heads: dict[tuple[str, str], str] = {}
        self.lose_after_apply = False

    @staticmethod
    def target_key(target: Mapping[str, Any]) -> str:
        return canonical_bytes(target).decode()

    def manifest(self) -> dict[str, Any]:
        return {
            "schema": "daimon-adapter-manifest/v0",
            "adapter_id": publication.PROVIDER_ADAPTER_ID,
            "authority": {
                "matrix_authority": False,
                "may_append_ledger": False,
                "may_issue_presence": False,
                "may_mint_membership": False,
                "may_sign_as_me": False,
            },
            "capabilities": ["inspect", "plan", "publish", "reconcile", "recover"],
            "contracts": [{"contract": "publisher-transaction", "versions": ["v1"]}],
            "limits": {
                "max_input_bytes": 17_825_792,
                "max_output_bytes": 2_097_152,
                "max_runtime_ms": 86_400_000,
            },
            "provider_kind": "artifact-store",
        }

    def plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        target = cast(Mapping[str, Any], request["target"])
        target_key = self.target_key(target)
        predecessor = cast(Mapping[str, Any] | None, request["predecessor"])
        sequence = 1
        if predecessor is not None:
            sequence = (
                self.receipts[cast(str, predecessor["receipt_id"])]["sequence"] + 1
            )
        roles = {"artifact", "audit-log", "evidence", "machine-index"}
        if target["kind"] == "llm-wiki":
            roles.add("visible-index")
        effects = []
        for role in sorted(roles):
            text = (
                request["content"]["text"]
                if role == "artifact"
                else f"{role}:{request['request_id']}:{sequence}\n"
            )
            raw = cast(str, text).encode()
            effects.append(
                {
                    "role": role,
                    "handle": f"{target['kind']}:{target['logical_id']}:{role}",
                    "media_type": "application/json"
                    if role in {"evidence", "machine-index"}
                    else "text/markdown; charset=utf-8",
                    "text": text,
                    "byte_length": len(raw),
                    "before_sha256": self.effect_heads.get((target_key, role)),
                    "after_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        core = {
            "schema": "dm.publisher.plan/v1",
            "adapter": {
                "id": publication.PROVIDER_ADAPTER_ID,
                "version": publication.PROVIDER_API_VERSION,
                "schema_version": 1,
            },
            "hmk_commit": publication.HMK_COMMIT,
            "request": copy.deepcopy(dict(request)),
            "request_hash": hashlib.sha256(canonical_bytes(request)).hexdigest(),
            "policy_hash": publication.PROVIDER_POLICY_HASH,
            "target": copy.deepcopy(dict(target)),
            "sequence": sequence,
            "predecessor_receipt_id": None
            if predecessor is None
            else predecessor["receipt_id"],
            "effects": effects,
            "scan": {"engine": "compaii-state-secret-scan/v1", "result": "clean"},
            "expected_result_hash": hashlib.sha256(
                canonical_bytes(
                    {"target": target, "sequence": sequence, "effects": effects}
                )
            ).hexdigest(),
        }
        return {**core, "plan_id": provider_id("plan", core)}

    def acquire(self, document: Mapping[str, Any]) -> dict[str, Any]:
        self.generation += 1
        core = {
            "schema": "dm.publisher.lease/v1",
            "target_kind": document["target_kind"],
            "namespace": document["namespace"],
            "owner": document["owner"],
            "generation": self.generation,
            "issued_at_ms": self.clock(),
            "expires_at_ms": self.clock() + cast(int, document["ttl_ms"]),
        }
        return {
            **core,
            "lease_id": provider_id("lease", core),
            "state": "active",
            "released_at_ms": None,
        }

    def apply(
        self, plan: Mapping[str, Any], lease: Mapping[str, Any]
    ) -> dict[str, Any]:
        plan_id = cast(str, plan["plan_id"])
        existing = self.receipt_by_plan.get(plan_id)
        if existing is not None:
            return copy.deepcopy(existing)
        request = cast(Mapping[str, Any], plan["request"])
        target = cast(Mapping[str, Any], plan["target"])
        effects = cast(list[Mapping[str, Any]], plan["effects"])
        receipt_effects = [
            {
                "role": effect["role"],
                "handle": effect["handle"],
                "sha256": effect["after_sha256"],
                "byte_length": effect["byte_length"],
            }
            for effect in effects
        ]
        by_role = {effect["role"]: effect for effect in receipt_effects}
        hmk_core = {
            "artifact_chapter_id": len(self.receipts) * 2 + 1,
            "evidence_chapter_id": len(self.receipts) * 2 + 2,
            "artifact_sha256": by_role["artifact"]["sha256"],
            "evidence_sha256": by_role["evidence"]["sha256"],
            "derived_from": True,
        }
        transaction_core = {
            "plan_id": plan_id,
            "lease_id": lease["lease_id"],
            "attempt": 1,
        }
        body = {
            "schema": "dm.publisher.receipt/v1",
            "request_id": request["request_id"],
            "request_hash": plan["request_hash"],
            "plan_id": plan_id,
            "expected_result_hash": plan["expected_result_hash"],
            "target": copy.deepcopy(dict(target)),
            "artifact_class": request["artifact_class"],
            "operation": request["operation"],
            "sequence": plan["sequence"],
            "predecessor_receipt_id": plan["predecessor_receipt_id"],
            "relation": copy.deepcopy(request["relation"]),
            "source_event_refs": copy.deepcopy(request["source"]["event_refs"]),
            "source_release_ref": copy.deepcopy(request["source"]["release_ref"]),
            "source_checkpoint_id": request["source"]["checkpoint"]["checkpoint_id"],
            "source_checkpoint_hash": request["source"]["checkpoint"][
                "checkpoint_hash"
            ],
            "source_checkpoint_high_waters": copy.deepcopy(
                request["source"]["checkpoint"]["high_waters"]
            ),
            "policy": copy.deepcopy(request["policy"]),
            "review": copy.deepcopy(request["review"]),
            "governance": copy.deepcopy(request["governance"]),
            "publisher_principal": request["publisher_principal"],
            "transaction_id": provider_id("transaction", transaction_core),
            "lease": {
                "lease_id": lease["lease_id"],
                "generation": lease["generation"],
            },
            "effects": receipt_effects,
            "artifact_sha256": request["content"]["sha256"],
            "audit_head_sha256": by_role["audit-log"]["sha256"],
            "hmk": {
                **hmk_core,
                "state_hash": hashlib.sha256(canonical_bytes(hmk_core)).hexdigest(),
            },
            "outcome": {
                "publish": "published" if plan["sequence"] == 1 else "superseded",
                "withdraw": "tombstoned",
                "rollback": "rolled-back",
            }[cast(str, request["operation"])],
            "committed_at_ms": self.clock(),
        }
        receipt_id = provider_id("receipt", body)
        receipt = {
            **body,
            "receipt_id": receipt_id,
            "receipt_hash": receipt_id.rsplit(":", 1)[-1],
        }
        self.receipts[receipt_id] = receipt
        self.receipt_by_plan[plan_id] = receipt
        target_key = self.target_key(target)
        for effect in receipt_effects:
            self.effect_heads[(target_key, cast(str, effect["role"]))] = cast(
                str, effect["sha256"]
            )
        if self.lose_after_apply:
            self.lose_after_apply = False
            raise ConnectionError("model response loss")
        return copy.deepcopy(receipt)

    def reconcile(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        stored = self.receipts.get(cast(str, receipt["receipt_id"]))
        target = cast(Mapping[str, Any], receipt["target"])
        target_key = self.target_key(target)
        verified = stored is not None and canonical_bytes(stored) == canonical_bytes(
            receipt
        )
        if verified:
            for effect in cast(list[Mapping[str, Any]], receipt["effects"]):
                if (
                    self.effect_heads.get((target_key, cast(str, effect["role"])))
                    != effect["sha256"]
                ):
                    verified = False
                    break
        return {
            "schema": "dm.publisher.reconciliation/v1",
            "receipt_id": receipt["receipt_id"],
            "target": copy.deepcopy(dict(target)),
            "status": "verified" if verified else "effect-truth-discrepancy",
        }

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation == "manifest":
            return self.manifest()
        if operation == "plan":
            return self.plan(cast(Mapping[str, Any], document["request"]))
        if operation == "acquire":
            return self.acquire(document)
        if operation == "apply":
            return self.apply(
                cast(Mapping[str, Any], document["plan"]),
                cast(Mapping[str, Any], document["lease"]),
            )
        if operation == "reconcile":
            return self.reconcile(cast(Mapping[str, Any], document["receipt"]))
        if operation == "release":
            return {**document["lease"], "state": "released"}
        raise RuntimeError("unexpected model operation")


class DM035PublicContractTests(unittest.TestCase):
    def test_checked_in_contracts_are_closed_and_self_verifying(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        event_schema = json.loads(
            (ROOT / "schemas" / "weave" / "v1" / "event.schema.json").read_bytes()
        )
        self.assertEqual(set(event_schema["properties"]["kind"]["enum"]), EVENT_KINDS)
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        self.assertEqual(index["compaii_state_commit"], COMPAII_STATE_COMMIT)
        self.assertEqual(
            index["hmk_commit"], "f10fd5c3089c0962920314c97e14bc024feffa7a"
        )
        values: dict[str, Any] = {}
        for entry in index["entries"]:
            raw = (VECTOR_ROOT / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            value = json.loads(raw)
            values[entry["path"]] = value
            self.assertEqual(
                validator.is_valid(value),
                entry["expect"] == "accept",
                entry["path"],
            )
        self.assertEqual(
            validate_publication_profile(values["profile.json"]),
            values["profile.json"],
        )
        self.assertEqual(
            validate_publication_policy(values["policy.json"]), values["policy.json"]
        )
        self.assertEqual(
            validate_publication_claim(values["claim.json"]), values["claim.json"]
        )
        self.assertEqual(
            validate_publication_acceptance(values["acceptance.json"]),
            values["acceptance.json"],
        )


class DM035MatrixProtocolTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.clock = MutableClock()
        self.reviewer_key = Ed25519PrivateKey.from_private_bytes(seed("dm035-model"))
        self.reviewer = reviewer_descriptor(
            "reviewer@model", self.reviewer_key.public_key()
        )
        self.policy = create_publication_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            reviewers=[self.reviewer],
            max_pending=8,
        )
        self.profile = create_publication_profile(source_instance="matrix:model")
        self.contents: dict[str, bytes] = {}
        self.model = ModelPublisherTransport(self.clock)
        self.journal = PublicationJournal(self.root_path / "model" / "journal.sqlite")
        self.coordinator = self.make_coordinator(
            self.model, self.journal, lambda _stage: None
        )
        self.source = self.append(
            self.ledger_a,
            "legion",
            self.state.being_ref,
            payload={"summary": "public model source"},
        )

    def make_coordinator(
        self,
        transport: ModelPublisherTransport,
        journal: PublicationJournal,
        fault: Any,
    ) -> PublicationCoordinator:
        return PublicationCoordinator(
            ledger=self.ledger_a,
            profile=self.profile,
            policy=self.policy,
            transport=transport,
            content_resolver=self.resolve,
            journal=journal,
            signer=self.signers["legion"],
            clock=self.clock,
            fault=fault,
        )

    def resolve(self, reference: Mapping[str, Any]) -> bytes:
        return self.contents[cast(str, reference["sha256"])]

    def draft(
        self,
        coordinator: PublicationCoordinator,
        *,
        number: int,
        document: str,
        predecessor: str | None = None,
    ) -> dict[str, Any]:
        raw = f"Reviewed public model {number}.".encode()
        content_ref = create_content_ref(raw)
        self.contents[content_ref["sha256"]] = raw
        return coordinator.draft(
            source_event_ids=[self.source["event_id"]],
            artifact_class="identity-summary",
            target_kind="llm-wiki",
            document=document,
            title=f"Model {number}",
            body_ref=content_ref,
            classification="public",
            license_name="CC-BY-SA-4.0",
            derivation_ref=f"derivation:matrix:model-{number}",
            operation="publish",
            predecessor_acceptance_event_id=predecessor,
            compensates_acceptance_event_id=None,
            release_event_id=None,
            provider_request_id=f"36000000-0000-4000-8000-{number:012d}",
            review_decision_id=f"36000000-0000-4000-9000-{number:012d}",
            requested_at_ms=self.clock(),
        )

    def submit(
        self,
        coordinator: PublicationCoordinator,
        proposal: Mapping[str, Any],
        number: int,
    ) -> dict[str, Any]:
        review = sign_publication_review(
            proposal,
            reviewer=self.reviewer,
            private_key=self.reviewer_key,
            issued_at_ms=self.clock() - 1,
            expires_at_ms=self.clock() + 600_000,
        )
        return coordinator.submit(
            proposal,
            review,
            client_id="dm035-model",
            rpc_request_id=f"36000000-0000-4000-a000-{number:012d}",
        )

    def claim(
        self,
        coordinator: PublicationCoordinator,
        event: Mapping[str, Any],
        number: int,
        generation: int,
    ) -> dict[str, Any]:
        return coordinator.claim(
            request_event_id=cast(str, event["event_id"]),
            claim_id=f"36000000-0000-4000-b000-{number:012d}",
            expected_generation=generation,
            lease_until_ms=self.clock() + 600_000,
        )

    def test_model_effect_truth_response_loss_and_monotonic_successor(self) -> None:
        first_event = self.submit(
            self.coordinator,
            self.draft(self.coordinator, number=1, document="model-effect"),
            1,
        )
        first_claim = self.claim(self.coordinator, first_event, 1, 0)
        self.model.lose_after_apply = True
        with self.assertRaisesRegex(PublicationError, "provider_unavailable"):
            self.coordinator.execute(claim_id=first_claim["claim_id"])
        first = self.coordinator.execute(claim_id=first_claim["claim_id"])
        self.assertEqual(first["acceptance"]["sequence"], 1)

        successor_event = self.submit(
            self.coordinator,
            self.draft(
                self.coordinator,
                number=2,
                document="model-effect",
                predecessor=first["event"]["event_id"],
            ),
            2,
        )
        successor_claim = self.claim(self.coordinator, successor_event, 2, 1)
        successor = self.coordinator.execute(claim_id=successor_claim["claim_id"])
        self.assertEqual(successor["acceptance"]["sequence"], 2)
        self.assertEqual(self.coordinator.queue()["items"][-1]["state"], "completed")
        target_key = self.model.target_key(successor["acceptance"]["target"])
        self.model.effect_heads[(target_key, "artifact")] = "0" * 64
        self.assertEqual(
            self.coordinator.reconcile(successor["event"]["event_id"])["status"],
            "effect-truth-discrepancy",
        )
        with self.assertRaisesRegex(PublicationError, "effect_truth_discrepancy"):
            self.coordinator.execute(claim_id=successor_claim["claim_id"])

    def test_model_recovers_both_matrix_acceptance_windows_exactly_once(self) -> None:
        for number, stage in enumerate(
            ("after_provider_receipt", "after_matrix_acceptance"), start=10
        ):
            with self.subTest(stage=stage):
                model = ModelPublisherTransport(self.clock)
                journal = PublicationJournal(
                    self.root_path / f"model-{number}" / "journal.sqlite"
                )

                def fail(value: str, expected: str = stage) -> None:
                    if value == expected:
                        raise Crash(expected)

                broken = self.make_coordinator(model, journal, fail)
                event = self.submit(
                    broken,
                    self.draft(broken, number=number, document=f"model-{number}"),
                    number,
                )
                claim = self.claim(broken, event, number, 0)
                with self.assertRaises(Crash):
                    broken.execute(claim_id=claim["claim_id"])
                recovered = self.make_coordinator(model, journal, lambda _stage: None)
                result = recovered.execute(claim_id=claim["claim_id"])
                self.assertEqual(
                    recovered.reconcile(result["event"]["event_id"])["status"],
                    "verified",
                )
                matches = [
                    item
                    for item in self.ledger_a.events(include_incomplete=False)
                    if item["kind"] == "publication.receipted"
                    and item["payload"]["request_event_id"] == event["event_id"]
                ]
                self.assertEqual(len(matches), 1)


class DM035PublicationTests(RootLedgerFixture):
    provider_root: ClassVar[Path]
    hmk_root: ClassVar[Path]
    provider_module: ClassVar[ModuleType]

    @classmethod
    def setUpClass(cls) -> None:
        configured = os.environ.get("COMPAII_STATE_CONTRACT_ROOT")
        cls.provider_root = (
            Path(configured).resolve()
            if configured
            else DEFAULT_PROVIDER_ROOT.resolve()
        )
        hmk_configured = os.environ.get("HMK_CONTRACT_ROOT")
        cls.hmk_root = (
            Path(hmk_configured).resolve()
            if hmk_configured
            else DEFAULT_HMK_ROOT.resolve()
        )
        if not (cls.provider_root / "matrix_publisher.py").is_file():
            raise unittest.SkipTest("pinned compaii-state provider unavailable")
        if not (cls.hmk_root / "scripts" / "memoryctl.py").is_file():
            raise unittest.SkipTest("pinned HMK provider unavailable")
        for path, expected in (
            (cls.provider_root, COMPAII_STATE_COMMIT),
            (
                cls.hmk_root,
                "f10fd5c3089c0962920314c97e14bc024feffa7a",
            ),
        ):
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=path,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if head != expected:
                if configured or hmk_configured:
                    raise AssertionError(
                        f"configured contract is not exact pin {expected}"
                    )
                raise unittest.SkipTest(
                    f"contract checkout is not exact pin {expected}"
                )
        cls.provider_module = load_provider(cls.provider_root)

    def setUp(self) -> None:
        super().setUp()
        self.clock = MutableClock()
        self.reviewer_key = Ed25519PrivateKey.from_private_bytes(seed("dm035-reviewer"))
        self.reviewer = reviewer_descriptor(
            "nico@localhost", self.reviewer_key.public_key()
        )
        self.policy = create_publication_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            reviewers=[self.reviewer],
            max_pending=8,
        )
        self.profile = create_publication_profile(source_instance="matrix:synthetic")
        self.contents: dict[str, bytes] = {}
        self.wiki = self.root_path / "wiki"
        project = self.wiki / "projects" / "daimon-matrix"
        project.mkdir(parents=True)
        (project / "index.md").write_text("# Daimon Matrix\n", encoding="utf-8")
        self.provider_api = self.provider_module.MatrixPublisher(
            wiki_root=self.wiki,
            projection_root=self.root_path / "state",
            runtime_root=self.root_path / "provider-runtime",
            hmk_root=self.hmk_root,
            hmk_base=self.root_path / "hmk",
            policy_path=self.provider_root / "policies" / "matrix-publisher-v1.json",
            clock_ms=self.clock,
        )
        self.transport = RealProviderTransport(self.provider_module, self.provider_api)
        self.coordinator = PublicationCoordinator(
            ledger=self.ledger_a,
            profile=self.profile,
            policy=self.policy,
            transport=self.transport,
            content_resolver=self.resolve,
            journal=PublicationJournal(
                self.root_path / "publication" / "journal.sqlite"
            ),
            signer=self.signers["legion"],
            clock=self.clock,
        )
        self.source = self.append(
            self.ledger_a,
            "legion",
            self.state.being_ref,
            payload={"summary": "synthetic publication source"},
        )

    def content(self, text: str) -> dict[str, Any]:
        raw = text.encode("utf-8")
        reference = create_content_ref(raw)
        self.contents[reference["sha256"]] = raw
        return reference

    def resolve(self, reference: Mapping[str, Any]) -> bytes:
        try:
            return self.contents[cast(str, reference["sha256"])]
        except KeyError as exception:
            raise FileNotFoundError("synthetic content absent") from exception

    def draft(
        self,
        *,
        number: int = 1,
        body: str | None = "Synthetic reviewed identity summary.",
        operation: str = "publish",
        artifact_class: str = "identity-summary",
        target_kind: str = "llm-wiki",
        document: str = "compaii",
        classification: str = "public",
        predecessor: str | None = None,
        compensates: str | None = None,
        release_event_id: str | None = None,
    ) -> dict[str, Any]:
        return self.coordinator.draft(
            source_event_ids=[self.source["event_id"]],
            artifact_class=artifact_class,
            target_kind=target_kind,
            document=document,
            title="CompAII",
            body_ref=None if body is None else self.content(body),
            classification=classification,
            license_name="CC-BY-SA-4.0",
            derivation_ref=f"derivation:matrix:synthetic-{number}",
            operation=operation,
            predecessor_acceptance_event_id=predecessor,
            compensates_acceptance_event_id=compensates,
            release_event_id=release_event_id,
            provider_request_id=f"35000000-0000-4000-8000-{number:012d}",
            review_decision_id=f"35000000-0000-4000-9000-{number:012d}",
            requested_at_ms=self.clock(),
        )

    def review(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        return sign_publication_review(
            proposal,
            reviewer=self.reviewer,
            private_key=self.reviewer_key,
            issued_at_ms=self.clock() - 1,
            expires_at_ms=self.clock() + 600_000,
        )

    def submit(self, proposal: Mapping[str, Any], *, number: int = 1) -> dict[str, Any]:
        return self.coordinator.submit(
            proposal,
            self.review(proposal),
            client_id="dm035-test",
            rpc_request_id=f"35000000-0000-4000-a000-{number:012d}",
        )

    def claim_execute(
        self,
        request_event: Mapping[str, Any],
        *,
        number: int = 1,
        expected_generation: int = 0,
    ) -> dict[str, Any]:
        claim = self.coordinator.claim(
            request_event_id=cast(str, request_event["event_id"]),
            claim_id=f"35000000-0000-4000-b000-{number:012d}",
            expected_generation=expected_generation,
            lease_until_ms=self.clock() + 600_000,
        )
        return self.coordinator.execute(claim_id=claim["claim_id"])

    def test_real_wiki_publish_acceptance_replay_and_provenance(self) -> None:
        proposal = self.draft()
        event = self.submit(proposal)
        verify_event(event, self.authority)
        self.assertEqual(self.coordinator.queue()["items"][0]["state"], "pending")
        result = self.claim_execute(event)
        acceptance = validate_publication_acceptance(result["acceptance"])
        verify_event(result["event"], self.authority)
        self.assertEqual(acceptance["provider_commit"], COMPAII_STATE_COMMIT)
        self.assertEqual(acceptance["provider_receipt"]["sequence"], 1)
        self.assertEqual(
            self.coordinator.reconcile(result["event"]["event_id"])["status"],
            "verified",
        )
        self.assertEqual(self.coordinator.queue()["items"][0]["state"], "completed")
        artifact = self.wiki / "projects" / "daimon-matrix" / "notes" / "compaii.md"
        self.assertIn("Synthetic reviewed identity summary.", artifact.read_text())
        self.assertEqual(
            self.coordinator.execute(claim_id=result["acceptance"]["claim_id"])[
                "event"
            ],
            result["event"],
        )

    def test_public_contracts_validate_and_regenerate_byte_identically(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        event_schema = json.loads(
            (ROOT / "schemas" / "weave" / "v1" / "event.schema.json").read_bytes()
        )
        self.assertEqual(set(event_schema["properties"]["kind"]["enum"]), EVENT_KINDS)
        registry = Registry().with_resource(
            schema["$id"], Resource.from_contents(schema)
        )
        event_validator = Draft202012Validator(
            event_schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        self.assertEqual(index["compaii_state_commit"], COMPAII_STATE_COMMIT)
        self.assertEqual(
            index["hmk_commit"], "f10fd5c3089c0962920314c97e14bc024feffa7a"
        )
        values: dict[str, Any] = {}
        for entry in index["entries"]:
            raw = (VECTOR_ROOT / entry["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            value = json.loads(raw)
            values[entry["path"]] = value
            self.assertEqual(
                validator.is_valid(value),
                entry["expect"] == "accept",
                entry["path"],
            )
        self.assertEqual(
            validate_publication_profile(values["profile.json"]),
            values["profile.json"],
        )
        self.assertEqual(
            validate_publication_policy(values["policy.json"]), values["policy.json"]
        )
        self.assertEqual(
            validate_publication_claim(values["claim.json"]), values["claim.json"]
        )
        self.assertEqual(
            validate_publication_acceptance(values["acceptance.json"]),
            values["acceptance.json"],
        )

        with TemporaryDirectory(prefix="dm035-vectors-") as directory:
            temporary = Path(directory)
            generated_sets = []
            generated_schemas = []
            for seed_value, timezone in (
                ("1", "UTC"),
                ("947", "America/Argentina/Cordoba"),
            ):
                output = temporary / f"vectors-{seed_value}"
                generated_schema = temporary / f"schema-{seed_value}.json"
                environment = os.environ.copy()
                environment.update(
                    {
                        "PYTHONHASHSEED": seed_value,
                        "TZ": timezone,
                        "LC_ALL": "C.UTF-8",
                    }
                )
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "tools/generate_dm035_vectors.py"),
                        "--provider-root",
                        str(self.provider_root),
                        "--hmk-root",
                        str(self.hmk_root),
                        "--out",
                        str(output),
                        "--schema",
                        str(generated_schema),
                    ],
                    check=True,
                    cwd=ROOT,
                    env=environment,
                    timeout=30,
                )
                generated_sets.append(
                    {
                        path.relative_to(output): path.read_bytes()
                        for path in output.rglob("*")
                        if path.is_file()
                    }
                )
                generated_schemas.append(generated_schema.read_bytes())
            expected = {
                path.relative_to(VECTOR_ROOT): path.read_bytes()
                for path in VECTOR_ROOT.rglob("*")
                if path.is_file()
            }
            self.assertEqual(generated_sets, [expected, expected])
            self.assertEqual(
                generated_schemas, [SCHEMA_PATH.read_bytes(), SCHEMA_PATH.read_bytes()]
            )
        request_event = self.submit(self.draft(number=70), number=70)
        result = self.claim_execute(request_event, number=70)
        event_validator.validate(request_event)
        event_validator.validate(result["event"])

    def test_journal_refuses_symlink_ancestors_and_cross_process_writer(self) -> None:
        outside = self.root_path / "outside"
        outside.mkdir(mode=0o700)
        linked = self.root_path / "linked-publication"
        linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(PublicationError, "parent_symlink"):
            PublicationJournal(linked / "journal.sqlite").initialize()

        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        release = context.Event()
        path = self.root_path / "process-publication" / "journal.sqlite"
        process = context.Process(
            target=hold_publication_journal,
            args=(str(path), ready, release),
        )
        process.start()
        try:
            self.assertTrue(ready.wait(5))
            journal = PublicationJournal(path)
            with (
                self.assertRaisesRegex(PublicationError, "writer_busy"),
                journal.exclusive(),
            ):
                self.fail("foreign process unexpectedly acquired writer lock")
        finally:
            release.set()
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
        self.assertEqual(process.exitcode, 0)

    def test_profile_policy_review_and_provider_pins_fail_closed(self) -> None:
        self.assertEqual(validate_publication_profile(self.profile), self.profile)
        self.assertEqual(validate_publication_policy(self.policy), self.policy)
        self.assertEqual(self.policy["provider"]["adapter_id"], PROVIDER_ADAPTER_ID)
        self.assertEqual(self.policy["provider"]["policy_hash"], PROVIDER_POLICY_HASH)
        changed = copy.deepcopy(self.profile)
        changed["provider_commit"] = "0" * 40
        with self.assertRaisesRegex(
            PublicationError, "unsupported_publication_profile"
        ):
            validate_publication_profile(changed)
        proposal = self.draft()
        review = self.review(proposal)
        review["signature"] = "A" * 86
        with self.assertRaisesRegex(PublicationError, "review_signature"):
            self.coordinator.submit(
                proposal,
                review,
                client_id="dm035-test",
                rpc_request_id="35000000-0000-4000-a000-000000000099",
            )

    def test_final_render_secret_policy_and_unsafe_target(self) -> None:
        with self.assertRaisesRegex(PublicationError, "final_render_secret"):
            self.draft(body="github_" + "pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        with self.assertRaisesRegex(PublicationError, "policy_refused"):
            self.draft(classification="private")
        with self.assertRaisesRegex(PublicationError, "document"):
            self.draft(document="../escape")
        private = self.draft(
            number=2,
            target_kind="compaii-state",
            classification="private",
            document="private-summary",
        )
        self.assertEqual(private["target"]["kind"], "compaii-state")

    def test_response_loss_retries_same_provider_effect(self) -> None:
        event = self.submit(self.draft())
        claim = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 600_000,
        )
        self.transport.lose_after_apply = True
        with self.assertRaisesRegex(PublicationError, "provider_unavailable"):
            self.coordinator.execute(claim_id=claim["claim_id"])
        result = self.coordinator.execute(claim_id=claim["claim_id"])
        self.assertEqual(result["acceptance"]["provider_receipt"]["sequence"], 1)
        receipt_files = list(
            (self.root_path / "provider-runtime" / "receipts").glob("*.json")
        )
        self.assertEqual(len(receipt_files), 1)

    def test_successor_withdrawal_and_rollback_are_monotonic(self) -> None:
        first = self.claim_execute(self.submit(self.draft(number=1)), number=1)
        first_event = first["event"]["event_id"]
        second = self.claim_execute(
            self.submit(
                self.draft(
                    number=2,
                    body="Reviewed successor summary.",
                    predecessor=first_event,
                ),
                number=2,
            ),
            number=2,
            expected_generation=1,
        )
        with self.assertRaisesRegex(PublicationError, "compensation_not_predecessor"):
            self.draft(
                number=30,
                operation="rollback",
                predecessor=second["event"]["event_id"],
                compensates=first_event,
            )
        withdrawn = self.claim_execute(
            self.submit(
                self.draft(
                    number=3,
                    body=None,
                    operation="withdraw",
                    predecessor=second["event"]["event_id"],
                ),
                number=3,
            ),
            number=3,
            expected_generation=2,
        )
        rolled = self.claim_execute(
            self.submit(
                self.draft(
                    number=4,
                    body="Reviewed forward rollback content.",
                    operation="rollback",
                    predecessor=withdrawn["event"]["event_id"],
                    compensates=withdrawn["event"]["event_id"],
                ),
                number=4,
            ),
            number=4,
            expected_generation=3,
        )
        self.assertEqual(
            [
                first["acceptance"]["sequence"],
                second["acceptance"]["sequence"],
                withdrawn["acceptance"]["sequence"],
                rolled["acceptance"]["sequence"],
            ],
            [1, 2, 3, 4],
        )
        self.assertEqual(
            withdrawn["acceptance"]["provider_receipt"]["outcome"], "tombstoned"
        )
        self.assertEqual(
            rolled["acceptance"]["provider_receipt"]["outcome"], "rolled-back"
        )

    def test_queue_cutoff_claim_generation_and_backpressure(self) -> None:
        event = self.submit(self.draft())
        queue = self.coordinator.queue()
        self.assertEqual(self.coordinator.queue(queue["cutoff"]), queue)
        changed = copy.deepcopy(queue["cutoff"])
        changed["events"] = []
        with self.assertRaisesRegex(PublicationError, "cutoff_mismatch"):
            self.coordinator.queue(changed)
        first = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 1_000,
        )
        with self.assertRaisesRegex(PublicationError, "target_claimed"):
            self.coordinator.claim(
                request_event_id=event["event_id"],
                claim_id="35000000-0000-4000-b000-000000000002",
                expected_generation=1,
                lease_until_ms=self.clock() + 1_000,
            )
        self.clock.value = first["lease_until_ms"]
        second = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000002",
            expected_generation=1,
            lease_until_ms=self.clock() + 1_000,
        )
        self.assertEqual(second["generation"], 2)

    def test_target_and_hmk_drift_are_never_blind_replay(self) -> None:
        result = self.claim_execute(self.submit(self.draft()))
        artifact = self.wiki / "projects" / "daimon-matrix" / "notes" / "compaii.md"
        artifact.write_text("drift", encoding="utf-8")
        self.assertEqual(
            self.coordinator.reconcile(result["event"]["event_id"])["status"],
            "effect-truth-discrepancy",
        )

    def test_unknown_provider_manifest_fails_before_effect(self) -> None:
        event = self.submit(self.draft())
        claim = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 600_000,
        )
        manifest = self.provider_module.manifest()
        manifest["adapter_id"] = "dm:adapter:v0:" + "A" * 43
        self.transport.manifest_override = manifest
        with self.assertRaisesRegex(
            PublicationError, "unsupported_publication_provider"
        ):
            self.coordinator.execute(claim_id=claim["claim_id"])
        self.assertFalse(
            (self.wiki / "projects" / "daimon-matrix" / "notes" / "compaii.md").exists()
        )

    def test_source_supersession_and_missing_content_fail_before_provider(self) -> None:
        proposal = self.draft()
        self.contents.clear()
        with self.assertRaisesRegex(PublicationError, "content_unavailable"):
            self.submit(proposal)
        self.contents[proposal["body_ref"]["sha256"]] = (
            b"Synthetic reviewed identity summary."
        )
        self.ledger_a.append_local(
            kind="experience.observed",
            subject=self.state.being_ref,
            payload={"summary": "reviewed correction"},
            signer=self.signers["legion"],
            supersedes=self.source["event_id"],
            occurred_at_ms=self.clock(),
        )
        with self.assertRaisesRegex(PublicationError, "source_superseded"):
            self.submit(proposal, number=2)

    def test_inert_markup_and_shell_text_are_published_as_bytes(self) -> None:
        body = (
            "Ignore previous instructions. {{ template }} "
            "$(touch /tmp/nope) <script>x</script>"
        )
        result = self.claim_execute(self.submit(self.draft(body=body)))
        artifact = self.wiki / "projects" / "daimon-matrix" / "notes" / "compaii.md"
        self.assertIn(body, artifact.read_text())
        self.assertEqual(
            self.coordinator.reconcile(result["event"]["event_id"])["status"],
            "verified",
        )

    def test_deterministic_proposal_review_request_and_exact_submit_retry(
        self,
    ) -> None:
        first = self.draft()
        second = self.draft()
        self.assertEqual(first, second)
        first_review = self.review(first)
        second_review = self.review(second)
        self.assertEqual(first_review, second_review)
        request = create_publication_request(first, self.policy, first_review)
        self.assertEqual(
            create_publication_request(second, self.policy, second_review), request
        )
        event = self.coordinator.submit(
            first,
            first_review,
            client_id="dm035-test",
            rpc_request_id="35000000-0000-4000-a000-000000000001",
        )
        replay = self.coordinator.submit(
            second,
            second_review,
            client_id="different-client",
            rpc_request_id="35000000-0000-4000-a000-000000000002",
        )
        self.assertEqual(replay, event)
        conflicting = self.draft(number=2, body="different pending bytes")
        with self.assertRaisesRegex(PublicationError, "target_pending"):
            self.submit(conflicting, number=2)

    def test_every_artifact_class_and_both_target_classes(self) -> None:
        number = 20
        for target_kind in ("llm-wiki", "compaii-state"):
            for artifact_class in (
                "identity-summary",
                "decision",
                "release",
                "documentation",
            ):
                with self.subTest(target=target_kind, artifact=artifact_class):
                    document = f"{artifact_class}-{number}"
                    proposal = self.draft(
                        number=number,
                        target_kind=target_kind,
                        document=document,
                        artifact_class=artifact_class,
                        classification="private"
                        if target_kind == "compaii-state"
                        else "public",
                        release_event_id=self.source["event_id"]
                        if artifact_class == "release"
                        else None,
                    )
                    event = self.submit(proposal, number=number)
                    result = self.claim_execute(
                        event, number=number, expected_generation=0
                    )
                    self.assertEqual(
                        result["acceptance"]["provider_receipt"]["artifact_class"],
                        artifact_class,
                    )
                    number += 1

    def test_historical_queue_cutoff_rebuild_is_stable(self) -> None:
        event = self.submit(self.draft())
        before = self.coordinator.queue()
        self.claim_execute(event)
        current = self.coordinator.queue()
        self.assertEqual(current["items"][0]["state"], "completed")
        rebuilt = self.coordinator.queue(before["cutoff"])
        self.assertEqual(rebuilt, before)
        self.assertEqual(rebuilt["items"][0]["state"], "pending")

    def test_substituted_provider_receipt_is_refused_then_exact_retry_accepts(
        self,
    ) -> None:
        event = self.submit(self.draft())
        claim = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 600_000,
        )
        self.transport.corrupt_apply = True
        with self.assertRaisesRegex(PublicationError, "receipt_binding"):
            self.coordinator.execute(claim_id=claim["claim_id"])
        self.assertIsNone(self.coordinator.queue()["items"][0]["acceptance_event_id"])
        result = self.coordinator.execute(claim_id=claim["claim_id"])
        self.assertEqual(result["acceptance"]["provider_receipt"]["sequence"], 1)

    def test_provider_precommit_crash_recovers_all_old_then_retries(self) -> None:
        event = self.submit(self.draft())
        claim = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 600_000,
        )

        def fail(stage: str) -> None:
            if stage == "after_hmk_link":
                raise Crash(stage)

        broken = self.provider_module.MatrixPublisher(
            wiki_root=self.wiki,
            projection_root=self.root_path / "state",
            runtime_root=self.root_path / "provider-runtime",
            hmk_root=self.hmk_root,
            hmk_base=self.root_path / "hmk",
            policy_path=self.provider_root / "policies" / "matrix-publisher-v1.json",
            clock_ms=self.clock,
            fault=fail,
        )
        self.transport.api = broken
        with self.assertRaises(Crash):
            self.coordinator.execute(claim_id=claim["claim_id"])
        artifact = self.wiki / "projects" / "daimon-matrix" / "notes" / "compaii.md"
        self.assertTrue(artifact.exists())
        recovered = self.provider_module.MatrixPublisher(
            wiki_root=self.wiki,
            projection_root=self.root_path / "state",
            runtime_root=self.root_path / "provider-runtime",
            hmk_root=self.hmk_root,
            hmk_base=self.root_path / "hmk",
            policy_path=self.provider_root / "policies" / "matrix-publisher-v1.json",
            clock_ms=self.clock,
        )
        self.assertEqual(recovered.recover()[0]["outcome"], "rolled-back")
        self.assertFalse(artifact.exists())
        self.transport.api = recovered
        result = self.coordinator.execute(claim_id=claim["claim_id"])
        self.assertEqual(
            self.coordinator.reconcile(result["event"]["event_id"])["status"],
            "verified",
        )

    def test_every_provider_and_matrix_commit_phase_recovers_and_retries(self) -> None:
        provider_stages = [
            "after_journal",
            "after_effect:artifact",
            "after_effect:audit-log",
            "after_effect:evidence",
            "after_effect:machine-index",
            "after_effect:visible-index",
            "after_hmk_artifact",
            "after_hmk_evidence",
            "after_hmk_link",
            "before_receipt",
            "after_receipt",
            "after_commit_marker",
            "after_response",
        ]
        cases = [("provider", stage) for stage in provider_stages] + [
            ("matrix", "after_provider_receipt"),
            ("matrix", "after_matrix_acceptance"),
        ]
        for offset, (owner, crash_stage) in enumerate(cases, start=100):
            with self.subTest(owner=owner, stage=crash_stage):
                case = self.root_path / f"phase-{offset}"
                wiki = case / "wiki"
                project = wiki / "projects" / "daimon-matrix"
                project.mkdir(parents=True)
                (project / "index.md").write_text("# Daimon Matrix\n")
                unrelated = project / "unrelated.md"
                unrelated.write_text("unrelated canonical Wiki content\n")

                def fail_provider(
                    stage: str,
                    expected: str = crash_stage,
                    expected_owner: str = owner,
                ) -> None:
                    if expected_owner == "provider" and stage == expected:
                        raise Crash(expected)

                api = self.provider_module.MatrixPublisher(
                    wiki_root=wiki,
                    projection_root=case / "state",
                    runtime_root=case / "provider-runtime",
                    hmk_root=self.hmk_root,
                    hmk_base=case / "hmk",
                    policy_path=self.provider_root
                    / "policies"
                    / "matrix-publisher-v1.json",
                    clock_ms=self.clock,
                    fault=fail_provider,
                )
                transport = RealProviderTransport(self.provider_module, api)

                def fail_matrix(
                    stage: str,
                    expected: str = crash_stage,
                    expected_owner: str = owner,
                ) -> None:
                    if expected_owner == "matrix" and stage == expected:
                        raise Crash(expected)

                journal = PublicationJournal(case / "matrix" / "journal.sqlite")
                coordinator = PublicationCoordinator(
                    ledger=self.ledger_a,
                    profile=self.profile,
                    policy=self.policy,
                    transport=transport,
                    content_resolver=self.resolve,
                    journal=journal,
                    signer=self.signers["legion"],
                    clock=self.clock,
                    fault=fail_matrix,
                )
                proposal = coordinator.draft(
                    source_event_ids=[self.source["event_id"]],
                    artifact_class="identity-summary",
                    target_kind="llm-wiki",
                    document=f"phase-{offset}",
                    title=f"Phase {offset}",
                    body_ref=self.content(f"Reviewed phase {offset}."),
                    classification="public",
                    license_name="CC-BY-SA-4.0",
                    derivation_ref=f"derivation:matrix:phase-{offset}",
                    operation="publish",
                    predecessor_acceptance_event_id=None,
                    compensates_acceptance_event_id=None,
                    release_event_id=None,
                    provider_request_id=f"35000000-0000-4000-8000-{offset:012d}",
                    review_decision_id=f"35000000-0000-4000-9000-{offset:012d}",
                    requested_at_ms=self.clock(),
                )
                request_event = coordinator.submit(
                    proposal,
                    self.review(proposal),
                    client_id="dm035-phase-test",
                    rpc_request_id=f"35000000-0000-4000-a000-{offset:012d}",
                )
                claim = coordinator.claim(
                    request_event_id=request_event["event_id"],
                    claim_id=f"35000000-0000-4000-b000-{offset:012d}",
                    expected_generation=0,
                    lease_until_ms=self.clock() + 600_000,
                )
                with self.assertRaises(Crash):
                    coordinator.execute(claim_id=claim["claim_id"])

                recovered_api = self.provider_module.MatrixPublisher(
                    wiki_root=wiki,
                    projection_root=case / "state",
                    runtime_root=case / "provider-runtime",
                    hmk_root=self.hmk_root,
                    hmk_base=case / "hmk",
                    policy_path=self.provider_root
                    / "policies"
                    / "matrix-publisher-v1.json",
                    clock_ms=self.clock,
                )
                recovered_api.recover()
                artifact = project / "notes" / f"phase-{offset}.md"
                committed_before_retry = owner == "matrix" or crash_stage in {
                    "after_commit_marker",
                    "after_response",
                }
                self.assertEqual(artifact.exists(), committed_before_retry)
                self.assertEqual(
                    unrelated.read_text(), "unrelated canonical Wiki content\n"
                )
                transport.api = recovered_api
                recovered = PublicationCoordinator(
                    ledger=self.ledger_a,
                    profile=self.profile,
                    policy=self.policy,
                    transport=transport,
                    content_resolver=self.resolve,
                    journal=journal,
                    signer=self.signers["legion"],
                    clock=self.clock,
                )
                result = recovered.execute(claim_id=claim["claim_id"])
                self.assertEqual(
                    recovered.reconcile(result["event"]["event_id"])["status"],
                    "verified",
                )
                self.assertEqual(
                    unrelated.read_text(), "unrelated canonical Wiki content\n"
                )
                accepted = [
                    event
                    for event in self.ledger_a.events(include_incomplete=False)
                    if event["kind"] == "publication.receipted"
                    and event["payload"]["request_event_id"]
                    == request_event["event_id"]
                ]
                self.assertEqual(len(accepted), 1)

    def test_two_matrix_writers_share_one_process_lock(self) -> None:
        event = self.submit(self.draft())
        claim = self.coordinator.claim(
            request_event_id=event["event_id"],
            claim_id="35000000-0000-4000-b000-000000000001",
            expected_generation=0,
            lease_until_ms=self.clock() + 600_000,
        )
        entered = threading.Event()
        release = threading.Event()
        self.transport.apply_entered = entered
        self.transport.apply_release = release
        with ThreadPoolExecutor(max_workers=1) as workers:
            future = workers.submit(
                self.coordinator.execute, claim_id=claim["claim_id"]
            )
            self.assertTrue(entered.wait(5))
            with self.assertRaisesRegex(PublicationError, "writer_busy"):
                self.coordinator.execute(claim_id=claim["claim_id"])
            release.set()
            result = future.result(timeout=5)
        self.assertEqual(result["acceptance"]["sequence"], 1)


if __name__ == "__main__":
    unittest.main()
