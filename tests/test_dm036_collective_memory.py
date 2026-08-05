from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import unittest
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from types import ModuleType
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)
from referencing import Registry, Resource

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.collective_memory import (
    COLLECTIVE_MEMORY_COMMIT,
    COLLECTIVE_SCHEMA_SHA256,
    CollectiveMemoryError,
    CollectivePublisherAdapter,
    CollectivePublisherJournal,
    CollectiveSourceAdapter,
    CollectiveSourceStore,
    assert_separate_collective_stores,
    create_publisher_manifest,
    create_publisher_profile,
    create_source_manifest,
    create_source_profile,
    evidence_issuer,
    sign_publication_evidence,
    validate_export_manifest,
    validate_publisher_acceptance_payload,
    validate_publisher_profile,
    validate_publisher_request_payload,
    validate_source_preview,
    validate_source_profile,
    validate_source_receipt,
)
from daimon_matrix.weave import EVENT_KINDS, verify_event
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed

ROOT = Path(__file__).resolve().parents[1]
COLLECTIVE_ROOT = Path(
    os.environ.get(
        "COLLECTIVE_MEMORY_CONTRACT_ROOT", str(ROOT.parent / "collective-memory")
    )
).resolve()
SCHEMA_PATH = ROOT / "schemas" / "collective-memory" / "v1" / "contracts.schema.json"
VECTOR_ROOT = ROOT / "vectors" / "collective-memory" / "v1"
PROVENANCE_PATH = ROOT / "provenance" / "collective-memory-exchange-v1.json"
UPSTREAM_SCHEMA = (
    COLLECTIVE_ROOT / "schemas" / "exchange" / "v1" / "contracts.schema.json"
)


class Crash(BaseException):
    pass


class MutableClock:
    def __init__(self, value: int = NOW) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def utc(self) -> dt.datetime:
        return dt.datetime.fromtimestamp(self.value / 1000, tz=dt.UTC)


def utc(value: int) -> str:
    return (
        dt.datetime.fromtimestamp(value / 1000, tz=dt.UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def load_upstream() -> ModuleType:
    name = "dm036_collective_exchange"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(
        name, COLLECTIVE_ROOT / "mapa" / "exchange.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("collective-memory exchange module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class TestProjectionRunner:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.generation = 0

    def snapshot(self, tx: Path) -> None:
        (tx / "projection.before").write_text(str(self.generation), encoding="ascii")

    def restore(self, tx: Path) -> None:
        self.generation = int((tx / "projection.before").read_text(encoding="ascii"))

    def build(self) -> None:
        self.generation += 1

    def verify(self, relative: str, content_hash: str) -> dict[str, str]:
        content = (self.root / relative).read_bytes()
        if hashlib.sha256(content).hexdigest() != content_hash:
            raise RuntimeError("projection content mismatch")
        return {
            "index_generation": str(self.generation),
            "ui_generation": f"ui:{self.generation}",
            "index_content_hash": content_hash,
        }


class UpstreamFixture:
    def __init__(
        self, base: Path, clock: MutableClock, subject_id: str, *, real: bool = False
    ) -> None:
        self.module = load_upstream()
        self.root = base / "collective-corpus"
        self.data = base / "collective-data"
        base.mkdir(mode=0o700)
        self.root.mkdir(mode=0o700)
        self.data.mkdir(mode=0o700)
        (self.root / "mapa").mkdir()
        (self.root / "mapa" / "public.md").write_text(
            "# Public collective source\n", encoding="utf-8"
        )
        self.config = self.module.ExchangeConfig.from_object(
            {
                "schema": "collective-exchange-config/v1",
                "producer_instance": "collective:test",
                "producer_release": "collective:release:test",
                "policy_version": "policy:v1",
                "targets": [
                    {
                        "target_id": "collective:article:alpha",
                        "relative_path": "published/alpha.md",
                    }
                ],
                "index_scope": "total",
            }
        )
        self.reader_capability = self.module.ExchangeCapability(
            "cap:test:reader", "export-reader", ("public",), b"r" * 32
        )
        self.publisher_capability = self.module.ExchangeCapability(
            "cap:test:publisher",
            "reviewed-publisher",
            ("collective:article:alpha",),
            b"p" * 32,
        )
        self.subject_key = Ed25519PrivateKey.from_private_bytes(seed("dm036-subject"))
        self.reviewer_key = Ed25519PrivateKey.from_private_bytes(seed("dm036-reviewer"))
        self.subject = evidence_issuer(subject_id, self.subject_key.public_key())
        self.reviewer = evidence_issuer(
            "human:collective-reviewer", self.reviewer_key.public_key()
        )
        valid_from = utc(clock.value - 86_400_000)
        valid_to = utc(clock.value + 86_400_000)
        self.trust = self.module.TrustStore.from_object(
            {
                "schema": "collective-exchange-trust/v1",
                "keys": [
                    {
                        "kid": self.subject["kid"],
                        "principal": self.subject["principal"],
                        "roles": ["subject-consent"],
                        "public_key": self.subject["public_key"],
                        "not_before": valid_from,
                        "not_after": valid_to,
                        "revoked_at": None,
                    },
                    {
                        "kid": self.reviewer["kid"],
                        "principal": self.reviewer["principal"],
                        "roles": ["independent-review"],
                        "public_key": self.reviewer["public_key"],
                        "not_before": valid_from,
                        "not_after": valid_to,
                        "revoked_at": None,
                    },
                ],
            }
        )
        self.catalog: dict[str, Any] = {
            "schema": "collective-export-catalog/v1",
            "policy_version": "policy:v1",
            "scope_id": "public",
            "entries": [
                {
                    "artifact_id": "artifact:test:v1",
                    "logical_id": "logical:test",
                    "relative_path": "mapa/public.md",
                    "media_type": "text/markdown; charset=utf-8",
                    "authors": ["author:test"],
                    "source_refs": [{"id": "source:test", "hash": "1" * 64}],
                    "license": "MIT",
                    "consent_scope": "public",
                    "classification": "public",
                    "predecessor_artifact_id": None,
                    "state": "active",
                }
            ],
        }
        self.export = self.module.ExportBoundary(
            self.root,
            self.data,
            self.config,
            self.reader_capability,
            lambda _scope: copy.deepcopy(self.catalog),
            clock=clock.utc,
        )
        self.projections = None if real else TestProjectionRunner(self.root)
        self.publication = self.module.PublicationBoundary(
            self.root,
            self.data,
            self.config,
            self.publisher_capability,
            self.trust,
            projection_runner=self.projections,
            clock=clock.utc,
        )

    def successor(self, *, tombstone: bool = False) -> None:
        if not tombstone:
            (self.root / "mapa" / "public.md").write_text(
                "# Public collective successor\n", encoding="utf-8"
            )
        self.catalog["entries"] = [
            {
                **self.catalog["entries"][0],
                "artifact_id": "artifact:test:tombstone"
                if tombstone
                else "artifact:test:v2",
                "relative_path": None if tombstone else "mapa/public.md",
                "predecessor_artifact_id": self.catalog["entries"][0]["artifact_id"],
                "state": "tombstone" if tombstone else "active",
            }
        ]


class SourceTransport:
    def __init__(self, upstream: UpstreamFixture) -> None:
        self.upstream = upstream
        self.corrupt_object = False
        self.mix_page = False
        self.fail = False
        self.page_calls = 0
        self.manifest_mutator: Callable[[dict[str, Any]], None] | None = None
        self.page_mutator: Callable[[dict[str, Any]], None] | None = None

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any] | bytes:
        if self.fail:
            raise ConnectionError("synthetic source outage")
        if operation == "manifest":
            if document["generation_id"] is not None:
                manifest = self.upstream.export.manifest(document["generation_id"])
            else:
                manifest = self.upstream.export.create(document["scope_id"])
            manifest = copy.deepcopy(manifest)
            if self.manifest_mutator is not None:
                self.manifest_mutator(manifest)
            return cast(Mapping[str, Any], manifest)
        if operation == "page":
            self.page_calls += 1
            page = self.upstream.export.page(
                document["generation_id"],
                cursor=document["cursor"],
                limit=document["limit"],
            )
            if self.mix_page:
                page = copy.deepcopy(page)
                page["manifest_hash"] = "0" * 64
            if self.page_mutator is not None:
                page = copy.deepcopy(page)
                self.page_mutator(page)
            return cast(Mapping[str, Any], page)
        if operation == "object":
            result = cast(
                bytes,
                self.upstream.export.object_bytes(
                    document["generation_id"], document["content_ref"]
                ),
            )
            return result + b"tamper" if self.corrupt_object else result
        raise RuntimeError("source direction cannot publish")


class PublisherTransport:
    def __init__(self, upstream: UpstreamFixture) -> None:
        self.upstream = upstream
        self.lose_after_apply = False
        self.corrupt_receipt = False
        self.preview_mutator: Callable[[dict[str, Any]], None] | None = None

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation == "preview":
            preview = copy.deepcopy(
                self.upstream.publication.preview(document["draft"])
            )
            if self.preview_mutator is not None:
                self.preview_mutator(preview)
            return cast(Mapping[str, Any], preview)
        if operation == "plan":
            return cast(
                Mapping[str, Any], self.upstream.publication.plan(document["request"])
            )
        if operation == "apply":
            receipt = self.upstream.publication.apply(
                document["request"], document["plan"]
            )
            if self.lose_after_apply:
                self.lose_after_apply = False
                raise ConnectionError("synthetic response loss")
            if self.corrupt_receipt:
                receipt = copy.deepcopy(receipt)
                receipt["body"]["target_id"] = "collective:article:other"
            return cast(Mapping[str, Any], receipt)
        if operation == "reconcile":
            try:
                return cast(
                    Mapping[str, Any],
                    self.upstream.publication.reconcile(document["receipt_id"]),
                )
            except self.upstream.module.ExchangeError as exception:
                if exception.code == "effect_truth_discrepancy":
                    raise CollectiveMemoryError(
                        "collective_effect_truth_discrepancy"
                    ) from exception
                raise
        if operation == "recover":
            return {"recovered": self.upstream.publication.recover()}
        raise RuntimeError("publisher direction cannot read exports")


class DM036ContractTests(unittest.TestCase):
    def test_pinned_upstream_and_closed_contracts(self) -> None:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=COLLECTIVE_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(head, COLLECTIVE_MEMORY_COMMIT)
        self.assertEqual(
            hashlib.sha256(UPSTREAM_SCHEMA.read_bytes()).hexdigest(),
            COLLECTIVE_SCHEMA_SHA256,
        )
        schema = json.loads(SCHEMA_PATH.read_bytes())
        Draft202012Validator.check_schema(schema)
        event_schema = json.loads(
            (ROOT / "schemas" / "weave" / "v1" / "event.schema.json").read_bytes()
        )
        self.assertEqual(set(event_schema["properties"]["kind"]["enum"]), EVENT_KINDS)
        upstream_index = json.loads(
            (
                COLLECTIVE_ROOT / "vectors" / "exchange" / "v1" / "index.json"
            ).read_bytes()
        )
        for entry in upstream_index["files"]:
            raw = (
                COLLECTIVE_ROOT / "vectors" / "exchange" / "v1" / entry["name"]
            ).read_bytes()
            self.assertEqual(len(raw), entry["size"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])

    def test_upstream_provenance_inventory_matches_exact_tree(self) -> None:
        provenance = json.loads(PROVENANCE_PATH.read_bytes())
        self.assertEqual(provenance["upstream"]["commit"], COLLECTIVE_MEMORY_COMMIT)
        tree = subprocess.run(
            ["git", "rev-parse", f"{COLLECTIVE_MEMORY_COMMIT}^{{tree}}"],
            cwd=COLLECTIVE_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(tree, provenance["upstream"]["tree"])
        for item in provenance["items"]:
            line = subprocess.run(
                ["git", "ls-tree", COLLECTIVE_MEMORY_COMMIT, "--", item["path"]],
                cwd=COLLECTIVE_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertTrue(line, item["path"])
            self.assertEqual(line.split()[2], item["git_blob_sha1"])
            raw = (COLLECTIVE_ROOT / item["path"]).read_bytes()
            self.assertEqual(len(raw), item["size"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])

    def test_direction_manifests_are_distinct_closed_dm018_denials(self) -> None:
        adapter_schema = json.loads(
            (
                ROOT / "schemas" / "adapters" / "v0" / "contracts.schema.json"
            ).read_bytes()
        )
        validator = Draft202012Validator(adapter_schema, format_checker=FormatChecker())
        source = create_source_manifest()
        publisher = create_publisher_manifest()
        validator.validate(source)
        validator.validate(publisher)
        self.assertNotEqual(source["adapter_id"], publisher["adapter_id"])
        self.assertNotEqual(source["contracts"], publisher["contracts"])
        self.assertTrue(all(value is False for value in source["authority"].values()))
        self.assertTrue(
            all(value is False for value in publisher["authority"].values())
        )
        self.assertNotIn("apply", source["capabilities"])
        self.assertNotIn("read", publisher["capabilities"])

    def test_matrix_vectors_are_canonical_closed_and_self_verifying(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        index = json.loads((VECTOR_ROOT / "index.json").read_bytes())
        self.assertEqual(index["upstream_commit"], COLLECTIVE_MEMORY_COMMIT)
        self.assertEqual(index["upstream_schema_sha256"], COLLECTIVE_SCHEMA_SHA256)
        validators = {
            "dm.collective-source.profile/v1": validate_source_profile,
            "dm.collective-source.preview/v1": validate_source_preview,
            "dm.collective-source.receipt/v1": validate_source_receipt,
            "dm.collective-publisher.profile/v1": validate_publisher_profile,
            "dm.collective-publisher.request/v1": validate_publisher_request_payload,
            "dm.collective-publisher.acceptance/v1": (
                validate_publisher_acceptance_payload
            ),
        }
        for entry in index["files"]:
            raw = (VECTOR_ROOT / entry["name"]).read_bytes()
            self.assertEqual(len(raw), entry["size"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), entry["sha256"])
            value = json.loads(raw)
            accepted = entry["expect"] == "accept"
            self.assertEqual(validator.is_valid(value), accepted, entry["name"])
            if accepted:
                self.assertEqual(validators[value["schema"]](value), value)


class DM036IntegrationTests(RootLedgerFixture):
    clock: MutableClock
    upstream: UpstreamFixture
    source_transport: SourceTransport
    publisher_transport: PublisherTransport
    source_store: CollectiveSourceStore
    publisher_journal: CollectivePublisherJournal
    source_adapter: CollectiveSourceAdapter
    publisher_adapter: CollectivePublisherAdapter
    source_event: dict[str, Any]

    def setUp(self) -> None:
        super().setUp()
        self.clock = MutableClock()
        self.upstream = UpstreamFixture(
            self.root_path / "upstream", self.clock, self.state.being_ref
        )
        self.source_transport = SourceTransport(self.upstream)
        self.publisher_transport = PublisherTransport(self.upstream)
        self.source_store = CollectiveSourceStore(
            self.root_path / "inbound" / "source.sqlite"
        )
        self.publisher_journal = CollectivePublisherJournal(
            self.root_path / "outbound" / "publisher.sqlite"
        )
        assert_separate_collective_stores(self.source_store, self.publisher_journal)
        self.source_adapter = self.make_source()
        self.publisher_adapter = self.make_publisher()
        self.source_event = self.append(
            self.ledger_a,
            "legion",
            self.state.being_ref,
            payload={"summary": "reviewed derived public source"},
        )

    def make_source(self, fault: Any = lambda _stage: None) -> CollectiveSourceAdapter:
        return CollectiveSourceAdapter(
            ledger=self.ledger_a,
            profile=create_source_profile(
                producer_instance="collective:test",
                producer_release="collective:release:test",
                policy_version="policy:v1",
                scope_id="public",
            ),
            transport=self.source_transport,
            store=self.source_store,
            signer=self.signers["legion"],
            clock=self.clock,
            fault=fault,
        )

    def assert_matrix_contract(self, value: Mapping[str, Any]) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

    def assert_event_contract(self, value: Mapping[str, Any]) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        event_schema = json.loads(
            (ROOT / "schemas" / "weave" / "v1" / "event.schema.json").read_bytes()
        )
        registry = Registry().with_resource(
            schema["$id"], Resource.from_contents(schema)
        )
        Draft202012Validator(
            event_schema,
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(value)

    def current_source(self) -> dict[str, Any]:
        current = self.source_store.current()
        self.assertIsNotNone(current)
        return cast(dict[str, Any], current)

    def make_publisher(
        self, fault: Any = lambda _stage: None
    ) -> CollectivePublisherAdapter:
        return CollectivePublisherAdapter(
            ledger=self.ledger_a,
            profile=create_publisher_profile(
                requester_id="operator:matrix",
                policy_version="policy:v1",
                target_ids=["collective:article:alpha"],
            ),
            transport=self.publisher_transport,
            journal=self.publisher_journal,
            signer=self.signers["legion"],
            consent_issuers={self.upstream.subject["principal"]: self.upstream.subject},
            review_issuers={
                self.upstream.reviewer["principal"]: self.upstream.reviewer
            },
            clock=self.clock,
            fault=fault,
        )

    def evidence(
        self, draft: Mapping[str, Any], preview: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        common = {
            "issued_at": utc(self.clock.value - 1),
            "not_before": utc(self.clock.value - 60_000),
            "not_after": utc(self.clock.value + 600_000),
        }
        consent = sign_publication_evidence(
            draft,
            preview,
            kind="consent",
            evidence_id="consent:test:v1",
            issuer=self.upstream.subject,
            private_key=self.upstream.subject_key,
            **common,
        )
        review = sign_publication_evidence(
            draft,
            preview,
            kind="review",
            evidence_id="review:test:v1",
            issuer=self.upstream.reviewer,
            private_key=self.upstream.reviewer_key,
            **common,
        )
        return consent, review

    def publication_draft(
        self,
        *,
        action: str = "publish",
        predecessor: Mapping[str, Any] | None = None,
        title: str = "Reviewed collective artifact",
        body: str = "Derived public bytes with exact Matrix provenance.",
    ) -> dict[str, Any]:
        return self.publisher_adapter.draft(
            source_event_ids=[self.source_event["event_id"]],
            subject_id=self.state.being_ref,
            target_id="collective:article:alpha",
            action=action,
            classification="public",
            title="" if action == "tombstone" else title,
            body="" if action == "tombstone" else body,
            predecessor_receipt_id=None
            if predecessor is None
            else predecessor["receipt_id"],
            predecessor_receipt_hash=None
            if predecessor is None
            else predecessor["receipt_hash"],
        )

    def publish(
        self,
        *,
        action: str = "publish",
        predecessor: Mapping[str, Any] | None = None,
        key: str = "idem:test:v1",
    ) -> dict[str, Any]:
        draft = self.publication_draft(action=action, predecessor=predecessor)
        preview = self.publisher_adapter.preview(draft)
        consent, review = self.evidence(draft, preview)
        event = self.publisher_adapter.submit(
            draft,
            preview,
            idempotency_key=key,
            consent=consent,
            review=review,
        )
        return self.publisher_adapter.execute(event["event_id"])

    def test_inbound_initial_retry_successor_and_tombstone_remain_quarantined(
        self,
    ) -> None:
        preview = self.source_adapter.preview()
        self.assertIsNone(self.source_store.current())
        receipt = self.source_adapter.apply(preview)
        self.assert_matrix_contract(receipt)
        self.assertEqual(receipt, self.source_adapter.apply(preview))
        self.assertEqual(receipt["body"]["outcomes"]["personal_memory_assertions"], 0)
        self.assertEqual(receipt["body"]["decision"], "quarantined")
        self.assertEqual(self.source_adapter.reconcile(receipt)["effect"], "verified")
        event = self.ledger_a.event(receipt["body"]["import_event_id"])
        self.assertIsNotNone(event)
        self.assert_event_contract(cast(Mapping[str, Any], event))
        verify_event(event, self.authority)
        self.assertFalse(
            any(item["kind"] == "memory.recorded" for item in self.ledger_a.events())
        )

        self.upstream.successor()
        second = self.source_adapter.apply(self.source_adapter.preview())
        self.assertEqual(
            second["body"]["predecessor_generation"], receipt["body"]["generation_id"]
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_source_effect_truth_discrepancy"
        ):
            self.source_adapter.apply(preview)
        self.upstream.successor(tombstone=True)
        third = self.source_adapter.apply(self.source_adapter.preview())
        self.assertEqual(third["body"]["outcomes"]["tombstoned"], 1)
        self.assertEqual(
            self.current_source()["body"]["artifacts"][0]["state"], "tombstone"
        )

    def test_inbound_invalid_refresh_and_outage_preserve_prior_generation(self) -> None:
        first = self.source_adapter.apply(self.source_adapter.preview())
        active = self.source_store.current()
        self.upstream.successor()
        self.source_transport.corrupt_object = True
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_content_mismatch"
        ):
            self.source_adapter.preview()
        self.assertEqual(self.source_store.current(), active)
        self.source_transport.corrupt_object = False
        self.source_transport.mix_page = True
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_mixed_generation"
        ):
            self.source_adapter.preview()
        self.assertEqual(
            self.current_source()["generation_id"],
            first["body"]["generation_id"],
        )
        self.source_transport.mix_page = False
        self.source_transport.fail = True
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_source_unavailable"
        ):
            self.source_adapter.preview()
        self.assertEqual(self.source_store.current(), active)

    def test_inbound_contract_rejects_adversarial_manifests_and_partial_page(
        self,
    ) -> None:
        manifest = self.upstream.export.create("public")

        def mutate_unknown(value: dict[str, Any]) -> None:
            value["body"]["host_path"] = "/private/corpus"

        def mutate_version(value: dict[str, Any]) -> None:
            value["schema"] = "collective-export-manifest/v2"

        def mutate_duplicate(value: dict[str, Any]) -> None:
            value["body"]["artifacts"].append(
                copy.deepcopy(value["body"]["artifacts"][0])
            )
            value["body"]["artifact_count"] += 1
            value["body"]["total_content_bytes"] *= 2

        def mutate_missing_author(value: dict[str, Any]) -> None:
            value["body"]["artifacts"][0]["authors"] = []

        def mutate_missing_license(value: dict[str, Any]) -> None:
            del value["body"]["artifacts"][0]["license"]

        def mutate_missing_consent(value: dict[str, Any]) -> None:
            del value["body"]["artifacts"][0]["consent_scope"]

        def mutate_missing_source(value: dict[str, Any]) -> None:
            value["body"]["artifacts"][0]["source_refs"] = []

        def mutate_media_type(value: dict[str, Any]) -> None:
            value["body"]["artifacts"][0]["media_type"] = "application/x-executable"

        def mutate_traversal(value: dict[str, Any]) -> None:
            value["body"]["artifacts"][0]["relative_path"] = "../../private"

        def mutate_oversized(value: dict[str, Any]) -> None:
            value["body"]["artifacts"][0]["content_length"] = 2 * 1024 * 1024 + 1
            value["body"]["total_content_bytes"] = 2 * 1024 * 1024 + 1

        mutations = {
            "unknown-field": mutate_unknown,
            "unknown-version": mutate_version,
            "duplicate-id": mutate_duplicate,
            "missing-author": mutate_missing_author,
            "missing-license": mutate_missing_license,
            "missing-consent": mutate_missing_consent,
            "missing-source": mutate_missing_source,
            "unknown-media-type": mutate_media_type,
            "traversal-field": mutate_traversal,
            "oversized-artifact": mutate_oversized,
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(manifest)
                mutation(candidate)
                with self.assertRaises(CollectiveMemoryError):
                    validate_export_manifest(candidate)

        self.source_transport.page_mutator = lambda page: page.update(
            {"artifacts": [], "next_cursor": None}
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_partial_or_mixed_generation"
        ):
            self.source_adapter.preview()
        self.assertIsNone(self.source_store.current())

    def test_inbound_rejects_artifact_fork_and_symlink_source(self) -> None:
        first = self.source_adapter.apply(self.source_adapter.preview())
        self.upstream.successor()
        self.upstream.catalog["entries"][0]["predecessor_artifact_id"] = (
            "artifact:test:alien"
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_source_invalid_response"
        ):
            self.source_adapter.apply(self.source_adapter.preview())
        self.assertEqual(
            self.current_source()["generation_id"],
            first["body"]["generation_id"],
        )

        symlink_upstream = UpstreamFixture(
            self.root_path / "symlink-upstream", self.clock, self.state.being_ref
        )
        outside = self.root_path / "outside.md"
        outside.write_text("must not cross symlink\n", encoding="utf-8")
        symlink = symlink_upstream.root / "mapa" / "linked.md"
        symlink.symlink_to(outside)
        symlink_upstream.catalog["entries"] = [
            {
                **symlink_upstream.catalog["entries"][0],
                "artifact_id": "artifact:test:symlink",
                "logical_id": "logical:test:symlink",
                "relative_path": "mapa/linked.md",
                "predecessor_artifact_id": None,
            }
        ]
        with self.assertRaisesRegex(
            symlink_upstream.module.ExchangeError, "unsafe_path"
        ):
            symlink_upstream.export.create("public")

    def test_inbound_paginates_bounded_generation_without_large_ledger_event(
        self,
    ) -> None:
        entries = []
        for number in range(257):
            name = f"item-{number:03d}"
            relative = f"mapa/{name}.md"
            (self.upstream.root / relative).write_text(
                f"# Collective item {number}\n", encoding="utf-8"
            )
            entries.append(
                {
                    "artifact_id": f"artifact:test:{name}",
                    "logical_id": f"logical:test:{name}",
                    "relative_path": relative,
                    "media_type": "text/markdown; charset=utf-8",
                    "authors": ["author:test"],
                    "source_refs": [
                        {"id": f"source:test:{name}", "hash": f"{number:064x}"}
                    ],
                    "license": "MIT",
                    "consent_scope": "public",
                    "classification": "public",
                    "predecessor_artifact_id": None,
                    "state": "active",
                }
            )
        self.upstream.catalog["entries"] = entries
        preview = self.source_adapter.preview()
        self.assertEqual(self.source_transport.page_calls, 2)
        receipt = self.source_adapter.apply(preview)
        self.assertEqual(receipt["body"]["artifact_count"], 257)
        event = self.ledger_a.event(receipt["body"]["import_event_id"])
        self.assertLess(len(canonical_bytes(event)), 16 * 1024)

    def test_inbound_recovers_crash_after_ledger_without_mixed_head(self) -> None:
        def fail(stage: str) -> None:
            if stage == "source-ledger-appended":
                raise Crash(stage)

        broken = self.make_source(fail)
        with self.assertRaises(Crash):
            broken.apply(broken.preview())
        self.assertIsNone(self.source_store.current())
        recovered = self.make_source()
        result = recovered.recover()
        self.assertEqual(result[0]["outcome"], "activated")
        receipt = self.source_store.recorded_receipt(result[0]["generation_id"])
        self.assertIsNotNone(receipt)
        self.assertEqual(
            recovered.reconcile(cast(Mapping[str, Any], receipt))["effect"],
            "verified",
        )

    def test_inbound_recovers_crash_after_prepare_before_ledger(self) -> None:
        def fail(stage: str) -> None:
            if stage == "source-prepared":
                raise Crash(stage)

        broken = self.make_source(fail)
        with self.assertRaises(Crash):
            broken.apply(broken.preview())
        self.assertIsNone(self.source_store.current())
        self.assertFalse(
            any(item["kind"] == "source.imported" for item in self.ledger_a.events())
        )
        recovered = self.make_source()
        result = recovered.recover()
        self.assertEqual(result[0]["outcome"], "activated")
        receipt = self.source_store.recorded_receipt(result[0]["generation_id"])
        self.assertIsNotNone(receipt)
        self.assertEqual(
            recovered.reconcile(cast(Mapping[str, Any], receipt))["effect"],
            "verified",
        )

    def test_inbound_rebuilds_active_projection_from_ledger_and_source_log(
        self,
    ) -> None:
        first = self.source_adapter.apply(self.source_adapter.preview())
        self.upstream.successor()
        second = self.source_adapter.apply(self.source_adapter.preview())
        with closing(self.source_store.connect()) as database:
            database.execute("UPDATE generations SET state='superseded'")
        self.assertIsNone(self.source_store.current())

        rebuilt = self.source_adapter.rebuild()
        self.assertEqual(rebuilt["accepted_generation_count"], 2)
        self.assertEqual(rebuilt["head_generation_id"], second["body"]["generation_id"])
        self.assertEqual(
            self.current_source()["generation_id"],
            second["body"]["generation_id"],
        )
        self.assertEqual(self.source_adapter.reconcile(second)["effect"], "verified")
        self.assertEqual(
            self.source_store.recorded_receipt(first["body"]["generation_id"]),
            first,
        )
        with closing(self.source_store.connect()) as database:
            database.execute(
                "UPDATE artifacts SET content=? WHERE generation_id=? "
                "AND content IS NOT NULL",
                (b"tampered source-log content", second["body"]["generation_id"]),
            )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_source_log_drift"
        ):
            self.source_adapter.reconcile(second)

    def test_inbound_offline_catch_up_walks_historical_manifests(self) -> None:
        first_manifest = self.upstream.export.create("public")
        self.upstream.successor()
        second_manifest = self.upstream.export.create("public")
        self.upstream.successor(tombstone=True)
        third_manifest = self.upstream.export.create("public")
        with self.assertRaisesRegex(CollectiveMemoryError, "collective_generation_gap"):
            self.source_adapter.preview()
        chain = self.source_adapter.preview_catch_up()
        self.assertEqual(
            [item["manifest"]["generation_id"] for item in chain],
            [
                first_manifest["generation_id"],
                second_manifest["generation_id"],
                third_manifest["generation_id"],
            ],
        )
        receipts = self.source_adapter.catch_up()
        self.assertEqual(len(receipts), 3)
        self.assertEqual(
            self.current_source()["generation_id"],
            third_manifest["generation_id"],
        )
        self.assertEqual(receipts[-1]["body"]["outcomes"]["tombstoned"], 1)

    def test_outbound_real_boundary_publish_response_loss_and_replay(self) -> None:
        draft = self.publication_draft()
        preview = self.publisher_adapter.preview(draft)
        consent, review = self.evidence(draft, preview)
        request_event = self.publisher_adapter.submit(
            draft,
            preview,
            idempotency_key="idem:response-loss",
            consent=consent,
            review=review,
        )
        self.publisher_transport.lose_after_apply = True
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_publisher_unavailable"
        ):
            self.publisher_adapter.execute(request_event["event_id"])
        result = self.publisher_adapter.execute(request_event["event_id"])
        replay = self.publisher_adapter.execute(request_event["event_id"])
        self.assertEqual(result, replay)
        self.assert_event_contract(request_event)
        self.assert_event_contract(result["event"])
        acceptance = validate_publisher_acceptance_payload(result["acceptance"])
        self.assert_matrix_contract(acceptance)
        self.assertEqual(
            self.publisher_adapter.reconcile(result["event"]["event_id"])["effect"],
            "verified",
        )
        self.assertEqual(
            acceptance["body"]["provider_receipt"]["body"]["source_refs"],
            [
                {
                    "id": self.source_event["event_id"],
                    "hash": self.source_event["content_hash"],
                }
            ],
        )
        verify_event(result["event"], self.authority)

    def test_outbound_concurrent_writers_accept_exactly_one_target_request(
        self,
    ) -> None:
        candidates = []
        for number in (1, 2):
            draft = self.publication_draft(
                title=f"Concurrent {number}", body=f"Concurrent reviewed body {number}."
            )
            preview = self.publisher_adapter.preview(draft)
            common = {
                "issued_at": utc(self.clock.value - 1),
                "not_before": utc(self.clock.value - 60_000),
                "not_after": utc(self.clock.value + 600_000),
            }
            consent = sign_publication_evidence(
                draft,
                preview,
                kind="consent",
                evidence_id=f"consent:concurrent:{number}",
                issuer=self.upstream.subject,
                private_key=self.upstream.subject_key,
                **common,
            )
            review = sign_publication_evidence(
                draft,
                preview,
                kind="review",
                evidence_id=f"review:concurrent:{number}",
                issuer=self.upstream.reviewer,
                private_key=self.upstream.reviewer_key,
                **common,
            )
            candidates.append((number, draft, preview, consent, review))

        def submit(candidate: tuple[Any, ...]) -> Any:
            number, draft, preview, consent, review = candidate
            try:
                return self.publisher_adapter.submit(
                    draft,
                    preview,
                    idempotency_key=f"idem:concurrent:{number}",
                    consent=consent,
                    review=review,
                )
            except CollectiveMemoryError as exception:
                return exception

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(submit, candidates))
        events = [item for item in outcomes if isinstance(item, dict)]
        errors = [item for item in outcomes if isinstance(item, CollectiveMemoryError)]
        self.assertEqual(len(events), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "collective_publication_target_pending")
        accepted = self.publisher_adapter.execute(events[0]["event_id"])
        self.assertEqual(
            accepted["acceptance"]["body"]["provider_receipt"]["body"]["status"],
            "committed",
        )

    def test_outbound_successor_and_reviewed_tombstone_are_monotonic(self) -> None:
        first = self.publish()
        first_receipt = first["acceptance"]["body"]["provider_receipt"]
        second = self.publish(
            action="successor", predecessor=first_receipt, key="idem:test:v2"
        )
        second_receipt = second["acceptance"]["body"]["provider_receipt"]
        self.assertEqual(second["event"]["supersedes"], first["event"]["event_id"])
        third = self.publish(
            action="tombstone", predecessor=second_receipt, key="idem:test:tombstone"
        )
        self.assertEqual(third["event"]["supersedes"], second["event"]["event_id"])
        self.assertEqual(
            third["acceptance"]["body"]["provider_receipt"]["body"]["after"]["state"],
            "tombstone",
        )

    def test_real_export_matrix_quarantine_publish_search_atlas_and_tombstone(
        self,
    ) -> None:
        real = UpstreamFixture(
            self.root_path / "real-upstream",
            self.clock,
            self.state.being_ref,
            real=True,
        )
        (real.root / "mapa" / "unrelated.md").write_text(
            "# Unrelated\n\nMust survive every transaction.\n", encoding="utf-8"
        )
        source_store = CollectiveSourceStore(
            self.root_path / "real-inbound" / "source.sqlite"
        )
        source_adapter = CollectiveSourceAdapter(
            ledger=self.ledger_a,
            profile=create_source_profile(
                producer_instance="collective:test",
                producer_release="collective:release:test",
                policy_version="policy:v1",
                scope_id="public",
            ),
            transport=SourceTransport(real),
            store=source_store,
            signer=self.signers["legion"],
            clock=self.clock,
        )
        inbound = source_adapter.apply(source_adapter.preview())
        self.assertEqual(inbound["body"]["decision"], "quarantined")

        journal = CollectivePublisherJournal(
            self.root_path / "real-outbound" / "publisher.sqlite"
        )
        publisher = CollectivePublisherAdapter(
            ledger=self.ledger_a,
            profile=create_publisher_profile(
                requester_id="operator:matrix",
                policy_version="policy:v1",
                target_ids=["collective:article:alpha"],
            ),
            transport=PublisherTransport(real),
            journal=journal,
            signer=self.signers["legion"],
            consent_issuers={real.subject["principal"]: real.subject},
            review_issuers={real.reviewer["principal"]: real.reviewer},
            clock=self.clock,
        )

        def reviewed(
            action: str,
            predecessor: Mapping[str, Any] | None,
            suffix: str,
        ) -> dict[str, Any]:
            draft = publisher.draft(
                source_event_ids=[self.source_event["event_id"]],
                subject_id=self.state.being_ref,
                target_id="collective:article:alpha",
                action=action,
                classification="public",
                title="" if action == "tombstone" else "Real Matrix publication",
                body=""
                if action == "tombstone"
                else "Visible through real FTS and Atlas projections.",
                predecessor_receipt_id=None
                if predecessor is None
                else predecessor["receipt_id"],
                predecessor_receipt_hash=None
                if predecessor is None
                else predecessor["receipt_hash"],
            )
            preview = publisher.preview(draft)
            common = {
                "issued_at": utc(self.clock.value - 1),
                "not_before": utc(self.clock.value - 60_000),
                "not_after": utc(self.clock.value + 600_000),
            }
            consent = sign_publication_evidence(
                draft,
                preview,
                kind="consent",
                evidence_id=f"consent:real:{suffix}",
                issuer=real.subject,
                private_key=real.subject_key,
                **common,
            )
            review = sign_publication_evidence(
                draft,
                preview,
                kind="review",
                evidence_id=f"review:real:{suffix}",
                issuer=real.reviewer,
                private_key=real.reviewer_key,
                **common,
            )
            request = publisher.submit(
                draft,
                preview,
                idempotency_key=f"idem:real:{suffix}",
                consent=consent,
                review=review,
            )
            return publisher.execute(request["event_id"])

        published = reviewed("publish", None, "publish")
        receipt = published["acceptance"]["body"]["provider_receipt"]
        with closing(
            sqlite3.connect(f"file:{real.data / 'index.db'}?mode=ro", uri=True)
        ) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM docs WHERE doc_id='published/alpha.md'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM docs WHERE doc_id='mapa/unrelated.md'"
                ).fetchone()[0],
                1,
            )
        ui_db = (real.data / "ui" / "ui_v2.db").resolve()
        with closing(sqlite3.connect(f"file:{ui_db}?mode=ro", uri=True)) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM docs WHERE doc_id='published/alpha.md'"
                ).fetchone()[0],
                1,
            )
        tombstone = reviewed("tombstone", receipt, "tombstone")
        self.assertEqual(
            tombstone["acceptance"]["body"]["provider_receipt"]["body"]["after"][
                "state"
            ],
            "tombstone",
        )
        self.assertTrue((real.root / "mapa" / "unrelated.md").is_file())
        self.assertNotEqual(source_store.path, real.data / "index.db")
        for database in (source_store.path, journal.path, real.data / "index.db"):
            self.assertFalse(Path(str(database) + "-wal").exists())
            self.assertFalse(Path(str(database) + "-shm").exists())

    def test_direction_separation_and_exact_review_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollectiveMemoryError, "direction_store_shared"):
            assert_separate_collective_stores(
                self.source_store,
                CollectivePublisherJournal(self.source_store.path),
            )
        with self.assertRaises(RuntimeError):
            self.source_transport("apply", {})
        with self.assertRaises(RuntimeError):
            self.publisher_transport("manifest", {})
        draft = self.publication_draft()
        preview = self.publisher_adapter.preview(draft)
        consent, review = self.evidence(draft, preview)
        changed = copy.deepcopy(draft)
        changed["body"] += " changed"
        with self.assertRaises(CollectiveMemoryError):
            self.publisher_adapter.submit(
                changed,
                preview,
                idempotency_key="idem:changed",
                consent=consent,
                review=review,
            )
        changed_checkpoint = copy.deepcopy(draft)
        changed_checkpoint["source_checkpoint"]["hash"] = "0" * 64
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_publication_checkpoint_mismatch"
        ):
            self.publisher_adapter.preview(changed_checkpoint)
        wrong_target_consent = copy.deepcopy(consent)
        wrong_target_consent["body"]["target_id"] = "collective:article:other"
        wrong_target_consent["signature"]["value"] = b64url(
            self.upstream.subject_key.sign(
                canonical_bytes(wrong_target_consent["body"])
            )
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_evidence_binding_mismatch"
        ):
            self.publisher_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:wrong-target-approval",
                consent=wrong_target_consent,
                review=review,
            )
        self_review = copy.deepcopy(review)
        self_review["body"]["issuer"] = self.state.being_ref
        with self.assertRaises(CollectiveMemoryError):
            self.publisher_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:self-review",
                consent=consent,
                review=self_review,
            )
        for secret_draft in (
            self.publication_draft(title="api_key=supersecretvalue"),
            self.publication_draft(body="Bearer " + "a" * 32),
            self.publication_draft(
                body="[private](https://operator:supersecret@internal.invalid/path)"
            ),
        ):
            with self.assertRaisesRegex(
                CollectiveMemoryError, "collective_secret_detected"
            ):
                self.publisher_adapter.preview(secret_draft)
        revoked_reviewer = evidence_issuer(
            self.upstream.reviewer["principal"],
            self.upstream.reviewer_key.public_key(),
            revoked_at_ms=self.clock.value - 1,
        )
        revoked_adapter = CollectivePublisherAdapter(
            ledger=self.ledger_a,
            profile=self.publisher_adapter.profile,
            transport=self.publisher_transport,
            journal=CollectivePublisherJournal(
                self.root_path / "outbound-revoked" / "publisher.sqlite"
            ),
            signer=self.signers["legion"],
            consent_issuers={self.upstream.subject["principal"]: self.upstream.subject},
            review_issuers={revoked_reviewer["principal"]: revoked_reviewer},
            clock=self.clock,
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_evidence_key_revoked"
        ):
            revoked_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:revoked-review",
                consent=consent,
                review=review,
            )

    def test_outbound_rejects_expired_or_revoked_consent_and_source_drift(
        self,
    ) -> None:
        draft = self.publication_draft()
        preview = self.publisher_adapter.preview(draft)
        _consent, review = self.evidence(draft, preview)
        expired = sign_publication_evidence(
            draft,
            preview,
            kind="consent",
            evidence_id="consent:expired",
            issuer=self.upstream.subject,
            private_key=self.upstream.subject_key,
            issued_at=utc(self.clock.value - 120_000),
            not_before=utc(self.clock.value - 120_000),
            not_after=utc(self.clock.value - 1),
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_evidence_expired"
        ):
            self.publisher_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:expired-consent",
                consent=expired,
                review=review,
            )

        revoked_subject = evidence_issuer(
            self.upstream.subject["principal"],
            self.upstream.subject_key.public_key(),
            revoked_at_ms=self.clock.value - 1,
        )
        revoked_adapter = CollectivePublisherAdapter(
            ledger=self.ledger_a,
            profile=self.publisher_adapter.profile,
            transport=self.publisher_transport,
            journal=CollectivePublisherJournal(
                self.root_path / "outbound-revoked-consent" / "publisher.sqlite"
            ),
            signer=self.signers["legion"],
            consent_issuers={revoked_subject["principal"]: revoked_subject},
            review_issuers={
                self.upstream.reviewer["principal"]: self.upstream.reviewer
            },
            clock=self.clock,
        )
        consent, _review = self.evidence(draft, preview)
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_evidence_key_revoked"
        ):
            revoked_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:revoked-consent",
                consent=consent,
                review=review,
            )

        self.ledger_a.append_local(
            kind="experience.observed",
            subject=self.state.being_ref,
            payload={"summary": "source correction"},
            signer=self.signers["legion"],
            supersedes=self.source_event["event_id"],
            occurred_at_ms=NOW,
        )
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_publication_source_drift"
        ):
            self.publisher_adapter.submit(
                draft,
                preview,
                idempotency_key="idem:source-drift",
                consent=consent,
                review=review,
            )

    def test_outbound_rejects_provider_preview_injection_untracked_tombstone_and_drift(
        self,
    ) -> None:
        draft = self.publication_draft()
        self.publisher_transport.preview_mutator = lambda value: value.update(
            {"host_path": "/private/corpus"}
        )
        with self.assertRaises(CollectiveMemoryError):
            self.publisher_adapter.preview(draft)
        self.publisher_transport.preview_mutator = None

        with self.assertRaises(CollectiveMemoryError):
            self.publisher_adapter.draft(
                source_event_ids=[self.source_event["event_id"]],
                subject_id=self.state.being_ref,
                target_id="collective:article:alpha",
                action="tombstone",
                classification="public",
                title="",
                body="",
                predecessor_receipt_id=None,
                predecessor_receipt_hash=None,
            )

        published = self.publish(key="idem:target-drift")
        target = self.upstream.root / "published" / "alpha.md"
        target.write_text("drifted outside the transaction\n", encoding="utf-8")
        with self.assertRaisesRegex(
            CollectiveMemoryError, "collective_effect_truth_discrepancy"
        ):
            self.publisher_adapter.reconcile(published["event"]["event_id"])

    def test_outbound_recovers_after_prepare_before_request_event(self) -> None:
        def fail(stage: str) -> None:
            if stage == "publisher-prepared":
                raise Crash(stage)

        broken = self.make_publisher(fail)
        draft = self.publication_draft()
        preview = broken.preview(draft)
        consent, review = self.evidence(draft, preview)
        with self.assertRaises(Crash):
            broken.submit(
                draft,
                preview,
                idempotency_key="idem:crash-prepared",
                consent=consent,
                review=review,
            )
        self.assertEqual(len(self.publisher_journal.rows(states=["prepared"])), 1)
        self.assertFalse(
            any(
                event["kind"] == "collective.publication.requested"
                for event in self.ledger_a.events()
            )
        )
        recovered = self.make_publisher()
        outcomes = recovered.recover()
        self.assertEqual(outcomes[0]["outcome"], "accepted")
        self.assertEqual(len(self.publisher_journal.rows(states=["accepted"])), 1)

    def test_outbound_recovers_after_effect_before_matrix_acceptance(self) -> None:
        def fail(stage: str) -> None:
            if stage == "publisher-effected":
                raise Crash(stage)

        broken = self.make_publisher(fail)
        draft = broken.draft(
            source_event_ids=[self.source_event["event_id"]],
            subject_id=self.state.being_ref,
            target_id="collective:article:alpha",
            action="publish",
            classification="public",
            title="Crash recovery",
            body="Exact reviewed recovery bytes.",
            predecessor_receipt_id=None,
            predecessor_receipt_hash=None,
        )
        preview = broken.preview(draft)
        consent, review = self.evidence(draft, preview)
        request_event = broken.submit(
            draft,
            preview,
            idempotency_key="idem:crash-effected",
            consent=consent,
            review=review,
        )
        with self.assertRaises(Crash):
            broken.execute(request_event["event_id"])
        recovered = self.make_publisher()
        outcomes = recovered.recover()
        self.assertEqual(outcomes[0]["outcome"], "accepted")
        rows = recovered.journal.rows(states=["accepted"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            recovered.reconcile(rows[0]["acceptance_event_id"])["effect"], "verified"
        )

    def test_outbound_recovers_after_acceptance_event_before_journal_commit(
        self,
    ) -> None:
        def fail(stage: str) -> None:
            if stage == "publisher-ledger-appended":
                raise Crash(stage)

        broken = self.make_publisher(fail)
        draft = self.publication_draft()
        preview = broken.preview(draft)
        consent, review = self.evidence(draft, preview)
        request = broken.submit(
            draft,
            preview,
            idempotency_key="idem:crash-acceptance-ledger",
            consent=consent,
            review=review,
        )
        with self.assertRaises(Crash):
            broken.execute(request["event_id"])
        self.assertEqual(len(self.publisher_journal.rows(states=["effected"])), 1)
        self.assertEqual(
            sum(
                event["kind"] == "collective.publication.receipted"
                for event in self.ledger_a.events()
            ),
            1,
        )
        recovered = self.make_publisher()
        outcomes = recovered.recover()
        self.assertEqual(outcomes[0]["outcome"], "accepted")
        self.assertEqual(
            sum(
                event["kind"] == "collective.publication.receipted"
                for event in self.ledger_a.events()
            ),
            1,
        )
