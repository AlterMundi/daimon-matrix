"""Deterministic two-being DM-081 source exchange and recovery journey.

The journey is deliberately isolated: it creates two disposable root identities,
uses only local SQLite files, grants one exact synthetic disclosure, and never
contacts a network, model, indexer, renderer, Matrix.org, or Cluster runtime.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import os
import stat
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import canonical_bytes
from .identity import (
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    create_synthetic_genesis_in_process,
    ed25519_public,
    key_descriptor,
    signing_descriptor,
    verify_genesis,
    x25519_public,
)
from .ledger import Ledger
from .sources import (
    SourceCAS,
    SourceError,
    SourceRegistry,
    assessment_series_id,
    claim_series_id,
    provenance_node_id,
    publication_binding_hash,
    publication_id,
    source_claim_binding_hash,
    source_content_ref,
    source_selector,
)
from .weave import BeingManifest, EventSigner, RootAuthority

NOW: Final = 1_800_000_000_000
MAX_TIME: Final = 2**53 - 1
REPORT_SCHEMA: Final = "dm.synthetic-source-report/v0"
_UUID_NAMESPACE: Final = uuid.UUID("81000000-0000-4000-8000-000000000000")


class SyntheticSourceError(RuntimeError):
    """The isolated source journey failed one of its claimed invariants."""


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"dm081:synthetic:{label}".encode()).digest()


def _uuid(label: str) -> str:
    return str(uuid.uuid5(_UUID_NAMESPACE, label))


def _uuid_factory(label: str) -> Any:
    counter = 0

    def factory() -> uuid.UUID:
        nonlocal counter
        counter += 1
        return uuid.uuid5(_UUID_NAMESPACE, f"{label}:{counter}")

    return factory


def _owner_root(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    if root.exists():
        info = root.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
        ):
            raise SyntheticSourceError("synthetic_source_root_rejected")
        if next(root.iterdir(), None) is not None:
            raise SyntheticSourceError("synthetic_source_root_not_empty")
    else:
        root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def _transport(label: str, principal_id: str) -> dict[str, Any]:
    return {
        "key": key_descriptor("Ed25519", ed25519_public(_seed(f"{label}:transport"))),
        "principal_id": principal_id,
        "scheme": "synthetic-loopback",
    }


@dataclass(frozen=True)
class _Identity:
    state: ControlState
    authority: RootAuthority
    origin: Mapping[str, str]
    signer: EventSigner


def _identity(label: str) -> _Identity:
    root_seeds = tuple(_seed(f"{label}:root:{index}") for index in range(3))
    recovery_seeds = tuple(_seed(f"{label}:recovery:{index}") for index in range(3))
    genesis = create_synthetic_genesis_in_process(
        root_seeds,
        2,
        recovery_seeds,
        2,
        created_at_ms=0,
        nonce=_seed(f"{label}:being"),
    )
    state = verify_genesis(genesis)
    signing_seed = _seed(f"{label}:signing")
    origin = {
        "body_ref": f"cluster:synthetic:{label}",
        "embodiment_id": f"embodiment:synthetic:{label}",
        "incarnation_id": f"incarnation:synthetic:{label}:0",
        "principal_id": f"synthetic-{label}@loopback",
    }
    credential = create_embodiment_credential(
        state,
        root_seeds,
        signing_seed,
        x25519_public(_seed(f"{label}:encryption")),
        embodiment_id=origin["embodiment_id"],
        body_ref=origin["body_ref"],
        purposes=["dm.we", "messages"],
        valid_from_ms=0,
        valid_until_ms=MAX_TIME,
        transport_principals=[_transport(label, origin["principal_id"])],
    )
    incarnation = create_incarnation_authorization(
        credential,
        signing_seed,
        incarnation_id=origin["incarnation_id"],
        incarnation_sequence=0,
        started_at_ms=0,
    )
    manifest = BeingManifest.from_value(
        {
            "being_ref": state.being_ref,
            "control_head": state.head,
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
            "history_binding_id": None,
            "revision": 1,
            "schema": "being-manifest/v2",
        }
    )
    authority = RootAuthority(
        manifest,
        state,
        {credential["artifact_id"]: credential},
        {incarnation["artifact_id"]: incarnation},
    )
    signer = EventSigner(signing_descriptor(signing_seed)["key_id"], signing_seed)
    return _Identity(state, authority, origin, signer)


class _Journey:
    def __init__(self, root: Path) -> None:
        self.root = _owner_root(root)
        self.publisher = _identity("publisher")
        self.receiver = _identity("receiver")
        if self.publisher.state.being_ref == self.receiver.state.being_ref:
            raise SyntheticSourceError("synthetic_source_identity_alias")
        publisher_root = self.root / "publisher"
        receiver_root = self.root / "receiver"
        publisher_root.mkdir(mode=0o700)
        receiver_root.mkdir(mode=0o700)
        self.publisher_ledger = Ledger(
            publisher_root / "local-ledger.sqlite3",
            authority=self.publisher.authority,
            local_origin=self.publisher.origin,
            clock=lambda: NOW,
            uuid_factory=_uuid_factory("publisher-local"),
        )
        self.receiver_ledger = Ledger(
            receiver_root / "local-ledger.sqlite3",
            authority=self.receiver.authority,
            local_origin=self.receiver.origin,
            clock=lambda: NOW,
            uuid_factory=_uuid_factory("receiver-local"),
        )
        self.publisher_receiver_replica = Ledger(
            publisher_root / "known-receiver.sqlite3",
            authority=self.receiver.authority,
            local_origin=self.receiver.origin,
            clock=lambda: NOW,
            uuid_factory=_uuid_factory("publisher-known-receiver"),
        )
        self.receiver_publisher_replica = Ledger(
            receiver_root / "known-publisher.sqlite3",
            authority=self.publisher.authority,
            local_origin=self.publisher.origin,
            clock=lambda: NOW,
            uuid_factory=_uuid_factory("receiver-known-publisher"),
        )
        self.publisher_cas = SourceCAS(publisher_root / "sources.sqlite3")
        self.receiver_cas = SourceCAS(receiver_root / "sources.sqlite3")
        self.core = {
            "canonical_reference": "urn:daimon:synthetic:source-journey",
            "kind": "project",
            "namespace": "dm081-synthetic",
            "schema": "daimon-source-core/v0",
        }
        self.selector = source_selector(self.core)

        def authorize(
            requester_me_id: str, source_identifier: str, classification: str
        ) -> bool:
            return (
                requester_me_id == self.receiver.state.being_ref
                and source_identifier == self.selector["source_id"]
                and classification in {"claim", "public", "origin-closure"}
            )

        self.publisher_registry = SourceRegistry(
            self.publisher_ledger,
            self.publisher_cas,
            clock=lambda: NOW,
            known_ledgers={
                self.receiver.state.being_ref: self.publisher_receiver_replica
            },
            disclosure_authorizer=authorize,
        )
        self.receiver_registry = SourceRegistry(
            self.receiver_ledger,
            self.receiver_cas,
            clock=lambda: NOW,
            known_ledgers={
                self.publisher.state.being_ref: self.receiver_publisher_replica
            },
        )
        self.publisher_registry.initialize()
        self.receiver_registry.initialize()
        self.artifacts: dict[str, Any] = {}

    def claim(
        self,
        *,
        sequence: int,
        predecessor: Mapping[str, Any] | None,
        action: str,
        issued_at_ms: int,
    ) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
        payload: dict[str, Any] = {
            "action": action,
            "claim_sequence": sequence,
            "claim_series_id": claim_series_id(
                self.publisher.state.being_ref, self.selector["source_id"]
            ),
            "claimant_control_position": {
                "embodiment_id": self.publisher.origin["embodiment_id"],
                "incarnation_id": self.publisher.origin["incarnation_id"],
                "manifest_hash": self.publisher.authority.manifest.digest,
            },
            "claimant_me_id": self.publisher.state.being_ref,
            "evidence_manifest_ref": None,
            "expires_at_ms": MAX_TIME if action == "assert" else None,
            "issued_at_ms": issued_at_ms,
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
        evidence_ref: dict[str, Any] | None = None
        manifest_ref: dict[str, Any] | None = None
        if action == "assert":
            evidence_ref = self.publisher_cas.put(
                f"independent evidence {sequence}".encode(), "text/plain"
            )
            manifest = {
                "claim_binding_hash": source_claim_binding_hash(payload),
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
            manifest_ref = self.publisher_cas.put_json(
                manifest,
                "application/vnd.daimon.source-evidence-manifest.v0+json",
            )
            payload["evidence_manifest_ref"] = manifest_ref
        event = self.publisher_registry.append_claim(
            payload, signer=self.publisher.signer
        )
        return event, evidence_ref, manifest_ref

    def publish(
        self, claim: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        content_ref = self.publisher_cas.put(
            b"bounded inert synthetic public knowledge", "text/plain"
        )
        original_ref = self.publisher_cas.put(
            b"bounded inert original notes", "text/plain"
        )
        source_uri = "hmk://dm081-synthetic/chapters/1"
        payload: dict[str, Any] = {
            "action": "publish",
            "classification": "public",
            "consent": "explicit",
            "content_ref": content_ref,
            "issued_at_ms": NOW + 1,
            "license": "CC BY-SA 4.0",
            "previous_publication_event_hash": None,
            "previous_publication_event_id": None,
            "provenance_manifest_ref": source_content_ref(
                b"placeholder", "application/octet-stream"
            ),
            "publication_id": publication_id(
                self.publisher.state.being_ref, source_uri
            ),
            "publication_sequence": 0,
            "publisher_claim_event_id": claim["event_id"],
            "publisher_me_id": self.publisher.state.being_ref,
            "reason": None,
            "schema": "daimon-source-publication/v0",
            "source_id": self.selector["source_id"],
            "source_uri": source_uri,
        }
        authors = [
            {
                "assertion": "publisher-declared",
                "evidence_refs": [],
                "subject_id": "external:synthetic-original-author",
                "subject_kind": "external",
            }
        ]
        original = {
            "authors": authors,
            "content_ref": original_ref,
            "kind": "original",
            "node_id": "placeholder",
            "source_uri": "urn:daimon:synthetic:original-notes",
        }
        original["node_id"] = provenance_node_id(original)
        output = {
            "authors": copy.deepcopy(authors),
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
        payload["provenance_manifest_ref"] = self.publisher_cas.put_json(
            provenance,
            "application/vnd.daimon.source-provenance-manifest.v0+json",
        )
        event = self.publisher_registry.append_publication(
            payload, signer=self.publisher.signer
        )
        return event, payload

    def assess(
        self,
        claim: Mapping[str, Any],
        evidence_ref: Mapping[str, Any],
        manifest_ref: Mapping[str, Any],
        cursor: Mapping[str, Any],
    ) -> dict[str, Any]:
        policy_ref = self.receiver_cas.put_json(
            {
                "decision": "admit-exact-evidence",
                "schema": "daimon-source-local-policy/v0",
            },
            "application/vnd.daimon.source-local-policy.v0+json",
        )
        snapshot = {
            "artifact_refs": [],
            "claim_event_ids": [claim["event_id"]],
            "content_refs": sorted(
                [copy.deepcopy(evidence_ref), copy.deepcopy(manifest_ref)],
                key=canonical_bytes,
            ),
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
        snapshot_ref = self.receiver_cas.put_json(
            snapshot,
            "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
        )
        return self.receiver_registry.append_assessment(
            {
                "assessment_sequence": 0,
                "assessment_series_id": assessment_series_id(
                    self.receiver.state.being_ref,
                    claim["payload"]["claim_series_id"],
                ),
                "assessor_me_id": self.receiver.state.being_ref,
                "claim_event_hash": claim["content_hash"],
                "claim_event_id": claim["event_id"],
                "claimant_me_id": claim["payload"]["claimant_me_id"],
                "decided_at_ms": NOW + 2,
                "disposition": "admitted",
                "evidence_manifest_ref": manifest_ref,
                "evidence_snapshot_ref": snapshot_ref,
                "policy_ref": policy_ref,
                "previous_assessment_event_id": None,
                "reason_codes": ["admitted:evidence-satisfied"],
                "schema": "daimon-source-assessment/v0",
                "source_id": self.selector["source_id"],
            },
            signer=self.receiver.signer,
        )

    def promote(
        self,
        publication: Mapping[str, Any],
        payload: Mapping[str, Any],
        cursor: Mapping[str, Any],
        claim: Mapping[str, Any],
    ) -> dict[str, Any]:
        policy_ref = self.receiver_cas.put_json(
            {
                "classification": payload["classification"],
                "consent": payload["consent"],
                "content_ref": payload["content_ref"],
                "content_safety_passed": True,
                "final_render_reviewed": True,
                "license": payload["license"],
                "provenance_manifest_ref": payload["provenance_manifest_ref"],
                "publication_event_hash": publication["content_hash"],
                "publication_event_id": publication["event_id"],
                "publication_id": payload["publication_id"],
                "schema": "daimon-source-promotion-policy/v0",
                "target_memory_category": "external-reference",
            },
            "application/vnd.daimon.source-promotion-policy.v0+json",
        )
        snapshot_ref = self.receiver_cas.put_json(
            {
                "artifact_refs": [],
                "claim_event_ids": [claim["event_id"]],
                "content_refs": sorted(
                    [payload["content_ref"], payload["provenance_manifest_ref"]],
                    key=canonical_bytes,
                ),
                "contradiction_refs": [],
                "observed_cursor_event_hash": cursor["content_hash"],
                "observed_cursor_event_id": cursor["event_id"],
                "schema": "daimon-source-policy-evidence-snapshot/v0",
                "source_id": self.selector["source_id"],
                "subject": {
                    "event_hash": publication["content_hash"],
                    "event_id": publication["event_id"],
                    "id": payload["publication_id"],
                    "kind": "publication",
                },
            },
            "application/vnd.daimon.source-policy-evidence-snapshot.v0+json",
        )
        return self.receiver_registry.promote(
            publication_identifier=payload["publication_id"],
            policy_ref=policy_ref,
            evidence_snapshot_ref=snapshot_ref,
            signer=self.receiver.signer,
            decided_at_ms=NOW + 3,
        )

    @staticmethod
    def _require(condition: bool, code: str) -> None:
        if not condition:
            raise SyntheticSourceError(code)

    def run(self) -> dict[str, Any]:
        starting = self.receiver_registry.create_cursor(
            self.selector, signer=self.receiver.signer, occurred_at_ms=NOW
        )["event"]
        starting_envelope = self.receiver_registry.cursor_envelope(starting)
        claim, evidence_ref, manifest_ref = self.claim(
            sequence=0, predecessor=None, action="assert", issued_at_ms=NOW
        )
        assert evidence_ref is not None and manifest_ref is not None
        publisher_claim_status = self.publisher_registry.status(self.selector)
        publication, publication_payload = self.publish(claim)
        self.publisher_registry.create_cursor(
            self.selector, signer=self.publisher.signer, occurred_at_ms=NOW + 1
        )

        denied_shapes: list[str] = []
        for requester in ("dm:being:v1:unknown-a", "dm:being:v1:unknown-b"):
            try:
                self.publisher_registry.diff(
                    selector=self.selector,
                    request_event_id=_uuid(f"denied:{requester}"),
                    requester_me_id=requester,
                    requester_cursor={
                        "observer_me_id": requester,
                        "schema": "dm.source-empty-cursor/v0",
                        "source_id": self.selector["source_id"],
                    },
                    max_items=1,
                    max_bytes=1_048_576,
                )
            except SourceError as error:
                denied_shapes.append(error.code)
        self._require(
            denied_shapes == ["source_disclosure_denied"] * 2,
            "synthetic_source_disclosure_oracle",
        )

        request_id = _uuid("initial-diff")
        first = self.publisher_registry.diff(
            selector=self.selector,
            request_event_id=request_id,
            requester_me_id=self.receiver.state.being_ref,
            requester_cursor=starting_envelope,
            max_items=1,
            max_bytes=4_194_304,
        )
        before_preview = (
            self.receiver_ledger.path.read_bytes(),
            self.receiver_cas.path.read_bytes(),
        )
        first_preview = self.receiver_registry.incoming(first)
        self._require(
            before_preview
            == (
                self.receiver_ledger.path.read_bytes(),
                self.receiver_cas.path.read_bytes(),
            ),
            "synthetic_source_incoming_mutated_state",
        )
        first_pull = self.receiver_registry.pull(
            operation_id=_uuid("pull-page-0"),
            bundle=first,
            preview=first_preview,
            signer=self.receiver.signer,
        )
        self._require(
            first_pull["achieved_cursor_hash"] == starting["content_hash"],
            "synthetic_source_partial_cursor_advanced",
        )
        second = self.publisher_registry.diff(
            selector=self.selector,
            request_event_id=request_id,
            requester_me_id=self.receiver.state.being_ref,
            requester_cursor=starting_envelope,
            max_items=1,
            max_bytes=4_194_304,
            continuation=first["continuation"],
        )
        second_preview = self.receiver_registry.incoming(second)
        operation_id = _uuid("pull-page-1")
        recovered_stages: list[str] = []
        for stage in ("prepared", "blobs", "events", "decisions", "cursor"):
            try:
                self.receiver_registry.pull(
                    operation_id=operation_id,
                    bundle=second,
                    preview=second_preview,
                    signer=self.receiver.signer,
                    _fault_after_stage=stage,
                )
            except SourceError as error:
                self._require(
                    error.code == "source_pull_fault_injected",
                    "synthetic_source_unexpected_recovery_error",
                )
                recovered_stages.append(stage)
        pull = self.receiver_registry.pull(
            operation_id=operation_id,
            bundle=second,
            preview=second_preview,
            signer=self.receiver.signer,
        )
        replay = self.receiver_registry.pull(
            operation_id=operation_id,
            bundle=second,
            preview=second_preview,
            signer=self.receiver.signer,
        )
        self._require(replay == pull, "synthetic_source_pull_replay_changed")
        achieved = next(
            event
            for event in self.receiver_ledger.events()
            if event["content_hash"] == pull["achieved_cursor_hash"]
        )
        receiver_quarantine = self.receiver_registry.status(self.selector)
        self._require(
            receiver_quarantine["claims"][0]["disposition"] == "quarantined",
            "synthetic_source_claim_auto_admitted",
        )
        initial_decision = self.receiver_ledger.event(pull["decision_event_ids"][0])
        if initial_decision is None:
            raise SyntheticSourceError("synthetic_source_import_decision_missing")
        self._require(
            initial_decision["payload"]["decision"] == "quarantined"
            and initial_decision["payload"]["target_memory_category"] is None,
            "synthetic_source_publication_auto_promoted",
        )

        assessment = self.assess(claim, evidence_ref, manifest_ref, achieved)
        receiver_admitted = self.receiver_registry.status(self.selector)
        before_remote_assessment = self.publisher_registry.status(self.selector)
        self.publisher_receiver_replica.ingest(
            self.receiver_ledger.events(), source="synthetic-receiver"
        )
        after_remote_assessment = self.publisher_registry.status(self.selector)
        self._require(
            receiver_admitted["claims"][0]["disposition"] == "admitted",
            "synthetic_source_local_assessment_not_applied",
        )
        self._require(
            before_remote_assessment == after_remote_assessment,
            "synthetic_source_remote_assessment_changed_policy",
        )
        promoted = self.promote(publication, publication_payload, achieved, claim)
        projection = promoted["projection"]
        self._require(
            projection["active"]
            and projection["target_memory_category"] == "external-reference"
            and projection["authors"][0]["authors"][0]["subject_id"]
            == "external:synthetic-original-author",
            "synthetic_source_attribution_or_target_lost",
        )

        tombstone_payload = {
            **copy.deepcopy(publication_payload),
            "action": "tombstone",
            "classification": None,
            "consent": None,
            "content_ref": None,
            "issued_at_ms": NOW + 10,
            "license": None,
            "previous_publication_event_hash": publication["content_hash"],
            "previous_publication_event_id": publication["event_id"],
            "provenance_manifest_ref": None,
            "publication_sequence": 1,
            "reason": "synthetic withdrawal",
        }
        tombstone = self.publisher_registry.append_publication(
            tombstone_payload, signer=self.publisher.signer
        )
        retraction, _, _ = self.claim(
            sequence=1,
            predecessor=claim,
            action="retract",
            issued_at_ms=NOW + 11,
        )
        reassertion, _, _ = self.claim(
            sequence=2,
            predecessor=retraction,
            action="assert",
            issued_at_ms=NOW + 12,
        )
        self.publisher_registry.create_cursor(
            self.selector, signer=self.publisher.signer, occurred_at_ms=NOW + 12
        )
        receiver_cursor = self.receiver_registry.latest_cursor(self.selector)
        assert receiver_cursor is not None
        terminal = self.publisher_registry.diff(
            selector=self.selector,
            request_event_id=_uuid("terminal-diff"),
            requester_me_id=self.receiver.state.being_ref,
            requester_cursor=receiver_cursor,
            max_items=8,
            max_bytes=8_388_608,
        )
        terminal_preview = self.receiver_registry.incoming(terminal)
        terminal_operation = _uuid("terminal-pull")
        terminal_pull = self.receiver_registry.pull(
            operation_id=terminal_operation,
            bundle=terminal,
            preview=terminal_preview,
            signer=self.receiver.signer,
        )
        terminal_replay = self.receiver_registry.pull(
            operation_id=terminal_operation,
            bundle=terminal,
            preview=terminal_preview,
            signer=self.receiver.signer,
        )
        final_status = self.receiver_registry.status(self.selector)
        final_projection = self.receiver_registry.promotion_projection(
            publication_payload["publication_id"]
        )
        self._require(
            terminal_pull == terminal_replay,
            "synthetic_source_terminal_pull_replay_changed",
        )
        self._require(
            final_status["claims"][0]["claim_event_id"] == reassertion["event_id"]
            and final_status["claims"][0]["disposition"] == "quarantined"
            and final_status["publications"][0]["state"] == "tombstoned",
            "synthetic_source_terminal_state_mismatch",
        )
        self._require(
            not final_projection["active"]
            and self.receiver_cas.get(publication_payload["content_ref"])
            == b"bounded inert synthetic public knowledge",
            "synthetic_source_tombstone_erased_or_active",
        )

        report = {
            "assessment_event_hash": assessment["content_hash"],
            "distinct_beings": True,
            "final": {
                "claim_disposition": final_status["claims"][0]["disposition"],
                "claim_sequence": final_status["claims"][0]["sequence"],
                "content_retained": True,
                "projection_active": final_projection["active"],
                "publication_state": final_status["publications"][0]["state"],
            },
            "initial": {
                "publisher_claim_intrinsic": publisher_claim_status["claims"][0][
                    "intrinsic_state"
                ],
                "receiver_claim_disposition": receiver_quarantine["claims"][0][
                    "disposition"
                ],
                "receiver_import_decision": initial_decision["payload"]["decision"],
            },
            "pagination": {
                "page_count": 2,
                "partial_cursor_unchanged": True,
                "terminal_cursor_hash": terminal_pull["achieved_cursor_hash"],
            },
            "promotion": {
                "author_preserved": "external:synthetic-original-author",
                "decision_event_hash": promoted["decision"]["content_hash"],
                "target_memory_category": projection["target_memory_category"],
            },
            "publisher_being_ref": self.publisher.state.being_ref,
            "pull": {
                "operation_id": operation_id,
                "recovered_stages": recovered_stages,
                "replay_byte_identical": canonical_bytes(replay)
                == canonical_bytes(pull),
            },
            "receiver_being_ref": self.receiver.state.being_ref,
            "remote_assessment_changed_publisher_policy": False,
            "schema": REPORT_SCHEMA,
            "source_id": self.selector["source_id"],
            "tombstone_event_hash": tombstone["content_hash"],
            "unauthorized_denial_code": denied_shapes[0],
        }
        self.artifacts = {
            "assessment-event": assessment,
            "final-projection": final_projection,
            "final-status": final_status,
            "initial-page-0": first,
            "initial-page-0-preview": first_preview,
            "initial-page-0-pull": first_pull,
            "initial-page-1": second,
            "initial-page-1-preview": second_preview,
            "initial-page-1-pull": pull,
            "promoted-projection": projection,
            "promotion-decision-event": promoted["decision"],
            "publication-event": publication,
            "reassertion-event": reassertion,
            "report": report,
            "selector": self.selector,
            "starting-cursor": starting_envelope,
            "terminal-bundle": terminal,
            "terminal-preview": terminal_preview,
            "terminal-pull": terminal_pull,
            "tombstone-event": tombstone,
        }
        return report


def run_synthetic_sources(root: Path) -> dict[str, Any]:
    """Run the complete isolated journey and return its secret-free report."""

    return _Journey(root).run()


def synthetic_source_evidence(root: Path) -> dict[str, Any]:
    """Return deterministic public wire evidence for vector generation."""

    journey = _Journey(root)
    journey.run()
    return copy.deepcopy(journey.artifacts)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        report = run_synthetic_sources(arguments.state_root)
    except (OSError, SourceError, SyntheticSourceError) as error:
        print(str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_bytes(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
