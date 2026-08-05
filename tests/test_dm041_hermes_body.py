#!/usr/bin/env python3
"""DM-041 isolated Hermes body contract and adversarial tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import unittest
import uuid
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any
from unittest import mock

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes
from daimon_matrix.client import (
    CLIENT_CONFIG_SCHEMA,
    ClientConfig,
    ClientError,
    LocalClient,
)
from daimon_matrix.cluster import BODY_SNAPSHOT_SCHEMA
from daimon_matrix.daemon import serve_forever
from daimon_matrix.hermes_body import (
    BOOTSTRAP_SCHEMA,
    CONTEXT_DOMAIN,
    CONTEXT_SCHEMA,
    EFFECT_DOMAIN,
    HERMES_COMMIT,
    HERMES_VERSION,
    PLUGIN_MANIFEST_TEMPLATE,
    PLUGIN_TEMPLATE,
    PROFILE_FILES,
    PROVIDER_NAME,
    PROVIDER_READY_SCHEMA,
    PROVIDER_TOOL_NAMES,
    SKILL_TEMPLATE,
    SOUL_TEMPLATE,
    HermesBodyAdapter,
    HermesBodyError,
    HermesBodyPlan,
    HermesProcess,
    MatrixMemoryProvider,
    RuntimeHandleJournal,
    _heads_high_water,
    bind_plan,
    create_park_receipt,
    create_park_request,
    create_plan_value,
    create_profile,
    plan_id,
    render_config,
    validate_hermes_context,
    validate_launch_receipt,
    validate_park_receipt,
    validate_plan,
    validate_provider_ready,
    verify_compatibility_source,
    verify_hermes_python,
    verify_profile,
    wait_provider_ready,
)
from daimon_matrix.local_api import create_capability
from daimon_matrix.memory_policy import (
    create_content_ref,
    create_memory_candidate,
    create_memory_policy,
)
from daimon_matrix.memory_projection import CURRENT_PROJECTION_DOMAIN
from daimon_matrix.projections import PROJECTION_DOMAIN
from daimon_matrix.runtime import load_runtime
from tests.test_dm024_runtime import PASSWORD, RuntimeFixture
from tools.generate_dm041_vectors import outputs as generated_outputs

NOW = 1_800_000_000_000
ROOT = Path(__file__).resolve().parents[1]


def derived(kind: str, label: str) -> str:
    return f"dm:{kind}:v1:" + b64url(hashlib.sha256(label.encode()).digest())


def supported_test_python(root: Path) -> Path:
    """Stage the runner in a private tree or emulate the unsupported runner."""

    current = tuple(int(item) for item in platform.python_version_tuple()[:2])
    if current >= (3, 14):
        launcher = root / "synthetic-python-3.13"
        if launcher.exists():
            launcher.chmod(0o700)
        launcher.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' "
            '\'{"implementation":"cpython","version":[3,13,0]}\'\n',
            encoding="utf-8",
        )
    else:
        # Hosted runners may install Python below a group-writable tool-cache
        # ancestor. Production correctly rejects that mutable path, so tests
        # stage the exact executable bytes below their owner-only root.
        launcher = root / "audited-python"
        shutil.copyfile(Path(sys.executable).resolve(), launcher)
    launcher.chmod(0o500)
    return launcher


def projection(
    being_ref: str, embodiment_id: str, manifest_hash: str
) -> dict[str, Any]:
    core = {
        "schema": "dm.we.projection/v1",
        "being_ref": being_ref,
        "manifest_hash": manifest_hash,
        "local_embodiment_id": embodiment_id,
        "entries": [],
    }
    return {
        **core,
        "projection_hash": hashlib.sha256(
            PROJECTION_DOMAIN + canonical_bytes(core)
        ).hexdigest(),
    }


class FakeClient:
    def __init__(
        self,
        *,
        status: Mapping[str, Any],
        scopes: list[Mapping[str, Any]],
        memory_entries: list[Mapping[str, Any]] | None = None,
    ) -> None:
        self.status = copy.deepcopy(dict(status))
        self.scopes = [copy.deepcopy(dict(item)) for item in scopes]
        self.observations: list[tuple[dict[str, Any], str | None]] = []
        self.memory_context_calls: list[dict[str, Any]] = []
        self.memory_entries = [
            copy.deepcopy(dict(item)) for item in (memory_entries or [])
        ]
        self.last_scope: dict[str, Any] | None = None

    def runtime_status(self) -> tuple[dict[str, Any], dict[str, Any]]:
        return {}, {"ok": True, "result": copy.deepcopy(self.status)}

    def prepare(
        self,
        method: str,
        params: Mapping[str, Any],
        *,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "method": method,
            "params": copy.deepcopy(dict(params)),
            "request_id": request_id,
        }

    def send(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("method") != "we.observe":
            raise ClientError("unsupported_client_method")
        _prepared, response = self.we_observe(
            request["params"], request_id=request.get("request_id")
        )
        return response

    def scope_me(self) -> tuple[dict[str, Any], dict[str, Any]]:
        if not self.scopes:
            raise ClientError("daemon_unavailable")
        value = self.scopes[0] if len(self.scopes) == 1 else self.scopes.pop(0)
        self.last_scope = copy.deepcopy(dict(value))
        return {}, {"ok": True, "result": copy.deepcopy(value)}

    def memory_context(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.last_scope is None:
            raise ClientError("daemon_unavailable")
        normalized = copy.deepcopy(dict(params))
        self.memory_context_calls.append(normalized)
        limit = normalized["limit"]
        assert isinstance(limit, int)
        selected = copy.deepcopy(self.memory_entries[:limit])
        projection_core = {
            "schema": "dm.memory.current-projection/v1",
            "being_ref": self.status["being_ref"],
            "manifest_hash": self.last_scope["manifest_hash"],
            "checkpoint": {
                "sequence": 0,
                "hash": hashlib.sha256(b"memory-checkpoint").hexdigest(),
            },
            "entries": selected,
            "total_active": len(self.memory_entries),
            "truncated": len(self.memory_entries) > len(selected),
        }
        memory_projection = {
            **projection_core,
            "projection_hash": hashlib.sha256(
                CURRENT_PROJECTION_DOMAIN + canonical_bytes(projection_core)
            ).hexdigest(),
        }
        query = unicodedata.normalize("NFC", normalized["query"])
        return {}, {
            "ok": True,
            "result": {
                "schema": "dm.memory.context/v1",
                "query_hash": hashlib.sha256(query.encode()).hexdigest(),
                "projection": memory_projection,
            },
        }

    def we_observe(
        self, params: Mapping[str, Any], *, request_id: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        normalized = copy.deepcopy(dict(params))
        self.observations.append((normalized, request_id))
        if self.last_scope is None:
            raise ClientError("daemon_unavailable")
        event = {
            "protocol": "dm.we.v1",
            "event_id": str(uuid.UUID(request_id)) if request_id else str(uuid.uuid4()),
            "being_ref": self.status["being_ref"],
            "manifest_hash": self.last_scope["manifest_hash"],
            "origin": copy.deepcopy(self.last_scope["origin"]),
            "sequence": 1,
            "previous_event_id": None,
            "occurred_at_ms": NOW,
            "causal_parents": [],
            "content_hash": hashlib.sha256(canonical_bytes(normalized)).hexdigest(),
            "kind": "experience.observed",
            "subject": normalized["subject"],
            "payload": normalized["payload"],
            "supersedes": None,
            "sensitivity": normalized["sensitivity"],
            "signature": {
                "alg": "Ed25519",
                "kid": derived("key", "fake-event-key"),
                "value": b64url(bytes(range(64))),
            },
        }
        return {}, {
            "ok": True,
            "result": {"schema": "dm.we.observe-result/v1", "event": event},
        }


class HermesBodyFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="dm041-test-")
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.profile_parent = self.root / "profiles"
        self.profile_parent.mkdir(mode=0o700)
        self.source = self.root / "hermes-source"
        self.source.mkdir(mode=0o700)
        source_file = self.source / "pyproject.toml"
        source_file.write_text('[project]\nversion = "0.19.0"\n')
        source_file.chmod(0o600)
        self.fake_contracts = {
            "pyproject.toml": hashlib.sha256(source_file.read_bytes()).hexdigest()
        }
        self.contract_patch = mock.patch(
            "daimon_matrix.hermes_body.HERMES_CONTRACT_DIGESTS",
            self.fake_contracts,
        )
        self.contract_patch.start()
        self.addCleanup(self.contract_patch.stop)
        self.python = supported_test_python(self.root)
        self.client_config = self.root / "client.json"
        self.client_config.write_text("{}")
        self.client_config.chmod(0o600)
        self.matrix_socket = self.root / "matrix.sock"
        self.capability_reader, self.capability_writer = os.pipe()
        self.ready_reader, self.ready_writer = os.pipe()
        self.addCleanup(self._close_descriptors)
        self.high_water = _heads_high_water([])
        self.bootstrap: dict[str, Any] = {
            "schema": BOOTSTRAP_SCHEMA,
            "being_ref": derived("being", "being-alpha"),
            "body_ref": derived("body", "body-alpha"),
            "embodiment_id": derived("embodiment", "embodiment-alpha"),
            "incarnation_id": derived("incarnation", "incarnation-alpha"),
            "matrix_session_id": derived("session", "matrix-alpha"),
            "matrix_high_water": self.high_water,
            "capability_set_hash": hashlib.sha256(b"capability").hexdigest(),
            "certificate_hash": hashlib.sha256(b"certificate").hexdigest(),
            "issued_at_ms": NOW - 10_000,
            "expires_at_ms": NOW + 3_600_000,
            "signature": {
                "alg": "Ed25519",
                "kid": derived("key", "bootstrap-key"),
                "value": b64url(bytes(range(64))),
            },
        }
        self.plan_value: dict[str, Any] = create_plan_value(
            bootstrap=self.bootstrap,
            model="synthetic/model",
            provider="synthetic",
            workspace_ref=derived("workspace", "workspace-alpha"),
        )
        self.plan: HermesBodyPlan = self.make_plan(self.profile_parent / "alpha")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _close_descriptors(self) -> None:
        for descriptor in (
            self.capability_reader,
            self.capability_writer,
            self.ready_reader,
            self.ready_writer,
        ):
            with suppress(OSError):
                os.close(descriptor)

    def make_plan(
        self, root: Path, *, value: Mapping[str, Any] | None = None
    ) -> HermesBodyPlan:
        return bind_plan(
            value or self.plan_value,
            profile_root=root,
            workspace=self.workspace,
            hermes_source=self.source,
            hermes_python=self.python,
            matrix_socket=self.matrix_socket,
            matrix_client_config=self.client_config,
            capability_fd=self.capability_reader,
            ready_fd=self.ready_writer,
        )

    def create(self) -> dict[str, Any]:
        return create_profile(
            self.plan,
            bootstrap_verifier=lambda value, at_ms: (
                value == self.bootstrap and at_ms == NOW
            ),
            clock=lambda: NOW,
        )

    def status(self) -> dict[str, Any]:
        return {
            "schema": "dm.runtime.status/v1",
            "being_ref": self.bootstrap["being_ref"],
            "integrity": "ok",
            "local_origin": self.origin(),
        }

    def origin(self) -> dict[str, Any]:
        return {
            "body_ref": self.bootstrap["body_ref"],
            "embodiment_id": self.bootstrap["embodiment_id"],
            "incarnation_id": self.bootstrap["incarnation_id"],
            "principal_id": derived("principal", "principal-alpha"),
        }

    def scope(
        self,
        heads: list[dict[str, Any]] | None = None,
        *,
        body_state: str = "running",
    ) -> dict[str, Any]:
        manifest_hash = hashlib.sha256(b"manifest").hexdigest()
        values = [] if heads is None else copy.deepcopy(heads)
        return {
            "schema": "dm.scope.me/v1",
            "being_ref": self.bootstrap["being_ref"],
            "manifest_hash": manifest_hash,
            "evaluated_at_ms": NOW,
            "origin": self.origin(),
            "credential_ref": derived("credential", "credential-alpha"),
            "incarnation_authorization_ref": derived(
                "authorization", "authorization-alpha"
            ),
            "body_capabilities": [],
            "body": {
                "schema": BODY_SNAPSHOT_SCHEMA,
                "body_ref": self.bootstrap["body_ref"],
                "embodiment_id": self.bootstrap["embodiment_id"],
                "incarnation_id": self.bootstrap["incarnation_id"],
                "observed_at_ms": NOW,
                "state": body_state,
                "resource_fences": [],
            },
            "heads": {
                "schema": "dm.we.heads/v1",
                "being_ref": self.bootstrap["being_ref"],
                "manifest_hash": manifest_hash,
                "sender": self.origin(),
                "heads": values,
            },
            "effective": projection(
                self.bootstrap["being_ref"],
                self.bootstrap["embodiment_id"],
                manifest_hash,
            ),
        }

    def memory_entry(self) -> dict[str, Any]:
        return {
            "event_id": "40000000-0000-4000-8000-000000000041",
            "event_hash": hashlib.sha256(b"memory-event").hexdigest(),
            "memory_id": "41000000-0000-4000-8000-000000000041",
            "sequence": 1,
            "category": "personal-insight",
            "author_me_id": self.bootstrap["being_ref"],
            "context": "context:synthetic",
            "content_ref": create_content_ref(
                sha256=hashlib.sha256(b"synthetic memory").hexdigest(),
                byte_length=len(b"synthetic memory"),
                media_type="text/plain",
                classification="personal",
            ),
            "evidence_refs": ["42000000-0000-4000-8000-000000000041"],
            "policy_id": derived("memory-policy", "synthetic"),
            "candidate_id": derived("memory-candidate", "synthetic"),
            "decision_id": derived("memory-decision", "synthetic"),
            "origin": self.origin(),
        }


class ContractAndProfileTests(HermesBodyFixture):
    def test_exact_plan_and_compatibility_contract(self) -> None:
        self.assertEqual(HERMES_VERSION, "0.19.0")
        self.assertEqual(HERMES_COMMIT, "0db1912911fafa384aa5ee0145929658a9d1dd33")
        self.assertEqual(validate_plan(self.plan_value), self.plan_value)
        self.assertEqual(
            verify_compatibility_source(self.source)["contract_digests"],
            self.fake_contracts,
        )
        changed = copy.deepcopy(self.plan_value)
        changed["hermes"]["version"] = "0.19.1"
        with self.assertRaisesRegex(HermesBodyError, "unsupported_hermes"):
            validate_plan(changed)
        python = verify_hermes_python(self.python)
        self.assertEqual(python["implementation"], "cpython")
        self.assertEqual(python["supported_interval"], ">=3.11,<3.14")
        self.source.chmod(0o777)
        with self.assertRaisesRegex(HermesBodyError, "hermes_source_untrusted"):
            verify_compatibility_source(self.source)
        self.source.chmod(0o700)

    def test_python_outside_audited_interval_fails_closed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=b'{"implementation":"cpython","version":[3,14,0]}\n',
            stderr=b"",
        )
        with (
            mock.patch(
                "daimon_matrix.hermes_body.subprocess.run", return_value=completed
            ),
            self.assertRaisesRegex(HermesBodyError, "unsupported_hermes_python"),
        ):
            verify_hermes_python(self.python)
        with mock.patch(
            "tests.test_dm041_hermes_body.platform.python_version_tuple",
            return_value=("3", "14", "0"),
        ):
            synthetic = supported_test_python(self.root)
            self.assertEqual(supported_test_python(self.root), synthetic)
        self.assertEqual(verify_hermes_python(synthetic)["version"], "3.13.0")

    def test_python_venv_launcher_is_preserved_and_target_is_bound(self) -> None:
        launcher = self.root / "python-venv-launcher"
        launcher.symlink_to(self.python)
        plan = bind_plan(
            self.plan_value,
            profile_root=self.profile_parent / "venv",
            workspace=self.workspace,
            hermes_source=self.source,
            hermes_python=launcher,
            matrix_socket=self.matrix_socket,
            matrix_client_config=self.client_config,
            capability_fd=self.capability_reader,
            ready_fd=self.ready_writer,
        )
        evidence = verify_hermes_python(plan.hermes_python)
        self.assertEqual(plan.hermes_python, launcher)
        self.assertEqual(
            evidence["executable_sha256"],
            hashlib.sha256(self.python.read_bytes()).hexdigest(),
        )

    def test_profile_is_deterministic_exclusive_and_native_memory_free(self) -> None:
        manifest = self.create()
        self.assertEqual(manifest, verify_profile(self.plan))
        self.assertEqual(len(manifest["matrix_package"]["modules"]), 34)
        self.assertEqual(
            len(manifest["matrix_package"]["tree_sha256"]),
            64,
        )
        self.assertEqual(
            sorted(item["name"] for item in manifest["files"]),
            list(PROFILE_FILES),
        )
        config = render_config(self.plan).decode()
        self.assertIn("memory_enabled: false", config)
        self.assertIn("provider: daimon-matrix", config)
        self.assertIn("    - memory", config)
        self.assertNotIn("API_KEY", config)
        self.assertEqual(
            (self.plan.profile_root / "SOUL.md").read_text(), SOUL_TEMPLATE
        )
        self.assertEqual(
            (self.plan.profile_root / "plugins/daimon-matrix/__init__.py").read_text(),
            PLUGIN_TEMPLATE,
        )
        self.assertEqual(
            (self.plan.profile_root / "plugins/daimon-matrix/plugin.yaml").read_text(),
            PLUGIN_MANIFEST_TEMPLATE,
        )
        self.assertEqual(
            (self.plan.profile_root / "skills/daimon-matrix/SKILL.md").read_text(),
            SKILL_TEMPLATE,
        )

        changed_package = copy.deepcopy(manifest["matrix_package"])
        changed_package["tree_sha256"] = "f" * 64
        with (
            mock.patch(
                "daimon_matrix.hermes_body.matrix_package_evidence",
                return_value=changed_package,
            ),
            self.assertRaisesRegex(HermesBodyError, "profile_manifest_drift"),
        ):
            verify_profile(self.plan)

    def test_existing_unsafe_and_native_state_fail_without_deletion(self) -> None:
        self.create()
        marker = self.plan.profile_root / "marker"
        marker.write_text("human")
        marker.chmod(0o600)
        with self.assertRaisesRegex(HermesBodyError, "profile_already_exists"):
            create_profile(
                self.plan,
                bootstrap_verifier=lambda _value, _at: True,
                clock=lambda: NOW,
            )
        self.assertEqual(marker.read_text(), "human")
        marker.unlink()
        memory = self.plan.profile_root / "MEMORY.md"
        memory.write_text("not canonical")
        memory.chmod(0o600)
        with self.assertRaisesRegex(HermesBodyError, "native_memory"):
            verify_profile(self.plan)

    def test_drift_duplicate_provider_and_path_substitution_fail_closed(self) -> None:
        self.create()
        plugin = self.plan.profile_root / "plugins/daimon-matrix/__init__.py"
        plugin.write_text("changed")
        with self.assertRaisesRegex(HermesBodyError, "profile_file_drift"):
            verify_profile(self.plan)
        plugin.write_text(PLUGIN_TEMPLATE)
        plugin.chmod(0o600)
        duplicate = self.plan.profile_root / "plugins/other"
        duplicate.mkdir(mode=0o700)
        (duplicate / "__init__.py").write_text("class MemoryProvider: pass")
        (duplicate / "__init__.py").chmod(0o600)
        with self.assertRaisesRegex(HermesBodyError, "unexpected_hermes"):
            verify_profile(self.plan)

    def test_profile_rejects_broad_modes_links_and_stale_plugin_backups(self) -> None:
        self.create()
        config = self.plan.profile_root / "config.yaml"
        config.chmod(0o640)
        with self.assertRaisesRegex(HermesBodyError, "profile_file_rejected"):
            verify_profile(self.plan)
        config.chmod(0o600)

        home = self.plan.profile_root / "home"
        home.mkdir(mode=0o700)
        link = home / "linked-soul"
        link.symlink_to(self.plan.profile_root / "SOUL.md")
        with self.assertRaisesRegex(HermesBodyError, "generated_state_unsafe"):
            verify_profile(self.plan)
        link.unlink()

        hardlink = home / "hardlinked-soul"
        os.link(self.plan.profile_root / "SOUL.md", hardlink)
        with self.assertRaisesRegex(HermesBodyError, "profile_file_rejected"):
            verify_profile(self.plan)
        hardlink.unlink()

        stale = self.plan.profile_root / "plugins" / "daimon-matrix.bak"
        stale.mkdir(mode=0o700)
        payload = stale / "__init__.py"
        payload.write_text("raise RuntimeError('must never load')")
        payload.chmod(0o600)
        with self.assertRaisesRegex(HermesBodyError, "unexpected_hermes"):
            verify_profile(self.plan)

    def test_profile_root_symlink_collision_is_never_followed_or_deleted(self) -> None:
        target = self.profile_parent / "human-profile"
        target.mkdir(mode=0o700)
        marker = target / "marker"
        marker.write_text("preserve")
        marker.chmod(0o600)
        linked_plan = self.make_plan(self.profile_parent / "linked")
        linked_plan.profile_root.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(HermesBodyError, "profile_already_exists"):
            create_profile(
                linked_plan,
                bootstrap_verifier=lambda _value, _at: True,
                clock=lambda: NOW,
            )
        self.assertEqual(marker.read_text(), "preserve")


class ProviderTests(HermesBodyFixture):
    def setUp(self) -> None:
        super().setUp()
        self.capability = create_capability(
            b"k" * 32,
            client_id="client:hermes-test",
            methods=["memory.context", "runtime.status", "scope.me", "we.observe"],
            not_before_ms=NOW - 60_000,
            not_after_ms=NOW + 60_000,
        )
        self.client_config.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origin(),
                }
            )
        )
        self.client_config.chmod(0o600)
        os.write(self.capability_writer, self.capability.key)
        os.close(self.capability_writer)
        self.create()

    def provider(self, client: FakeClient) -> MatrixMemoryProvider:
        provider = MatrixMemoryProvider(
            self.plan.profile_root / "plugins" / PROVIDER_NAME
        )
        self.assertTrue(provider.is_available())
        with (
            mock.patch("daimon_matrix.hermes_body.LocalClient", return_value=client),
            mock.patch("daimon_matrix.hermes_body.time.time", return_value=NOW / 1000),
        ):
            provider.initialize("hermes-session-alpha", agent_context="primary")
        return provider

    def test_real_provider_contract_initializes_and_emits_bounded_ready(self) -> None:
        client = FakeClient(status=self.status(), scopes=[self.scope()])
        provider = self.provider(client)
        raw = os.read(self.ready_reader, 65536)
        ready = validate_provider_ready(json.loads(raw), self.plan)
        self.assertEqual(ready["schema"], PROVIDER_READY_SCHEMA)
        self.assertEqual(ready["plan_id"], plan_id(self.plan.value))
        self.assertEqual(provider.name, PROVIDER_NAME)
        self.assertEqual(
            tuple(schema["name"] for schema in provider.get_tool_schemas()),
            PROVIDER_TOOL_NAMES,
        )

    def test_prefetch_is_inert_bounded_current_and_turn_sync_is_noop(self) -> None:
        client = FakeClient(
            status=self.status(),
            scopes=[self.scope(), self.scope()],
            memory_entries=[self.memory_entry()],
        )
        provider = self.provider(client)
        context = provider.prefetch(
            "synthetic question", session_id="hermes-session-alpha"
        )
        prefix, encoded = context.split("\n", 1)
        self.assertIn("inert attributed data", prefix)
        value = json.loads(encoded)
        self.assertEqual(value["schema"], CONTEXT_SCHEMA)
        self.assertEqual(value["entries"], [self.memory_entry()])
        self.assertEqual(
            value["entries"][0]["content_ref"]["classification"], "personal"
        )
        self.assertEqual(client.memory_context_calls[-1]["query"], "synthetic question")
        core = {key: item for key, item in value.items() if key != "context_id"}
        expected = "dm:hermes-context:v1:" + b64url(
            hashlib.sha256(CONTEXT_DOMAIN + canonical_bytes(core)).digest()
        )
        self.assertEqual(value["context_id"], expected)
        provider.sync_turn("private user", "private assistant", messages=[])
        self.assertEqual(client.observations, [])

    def test_explicit_observation_is_idempotent_proposal_not_memory(self) -> None:
        client = FakeClient(
            status=self.status(), scopes=[self.scope(), self.scope(), self.scope()]
        )
        provider = self.provider(client)
        operation_id = "40000000-0000-4000-8000-000000000041"
        result = json.loads(
            provider.handle_tool_call(
                "matrix_propose_observation",
                {"statement": "synthetic observation", "operation_id": operation_id},
            )
        )
        self.assertEqual(result["schema"], "dm.hermes-body.effect-receipt/v1")
        self.assertFalse(result["adopted"])
        receipt_core = {
            key: value for key, value in result.items() if key != "receipt_id"
        }
        self.assertEqual(
            result["receipt_id"],
            "dm:hermes-effect:v1:"
            + b64url(
                hashlib.sha256(EFFECT_DOMAIN + canonical_bytes(receipt_core)).digest()
            ),
        )
        self.assertEqual(client.observations[0][1], operation_id)
        payload = client.observations[0][0]["payload"]
        self.assertEqual(payload["schema"], "dm.hermes-body.observation/v1")
        self.assertNotIn("memory", payload)

    def test_wrong_session_expiry_and_high_water_regression_disclose_nothing(
        self,
    ) -> None:
        head = {
            "incarnation_id": self.bootstrap["incarnation_id"],
            "max_sequence": 1,
            "tip_event_id": "40000000-0000-4000-8000-000000000001",
            "tip_hash": hashlib.sha256(b"tip").hexdigest(),
        }
        client = FakeClient(
            status=self.status(),
            scopes=[
                self.scope(),
                self.scope([head]),
                self.scope([head]),
                self.scope(),
            ],
        )
        provider = self.provider(client)
        self.assertEqual(provider.prefetch("q", session_id="wrong-session"), "")
        self.assertTrue(provider.prefetch("q", session_id="hermes-session-alpha"))
        self.assertEqual(provider.prefetch("q", session_id="hermes-session-alpha"), "")

    def test_current_cluster_presence_is_required(self) -> None:
        stopped = FakeClient(
            status=self.status(), scopes=[self.scope(body_state="stopped")]
        )
        provider = MatrixMemoryProvider(
            self.plan.profile_root / "plugins" / PROVIDER_NAME
        )
        with (
            mock.patch("daimon_matrix.hermes_body.LocalClient", return_value=stopped),
            mock.patch("daimon_matrix.hermes_body.time.time", return_value=NOW / 1000),
            self.assertRaisesRegex(HermesBodyError, "body_presence_not_current"),
        ):
            provider.initialize("hermes-session-alpha", agent_context="primary")

    def test_stable_read_high_water_is_required(self) -> None:
        head = {
            "incarnation_id": self.bootstrap["incarnation_id"],
            "max_sequence": 1,
            "tip_event_id": "40000000-0000-4000-8000-000000000002",
            "tip_hash": hashlib.sha256(b"new-tip").hexdigest(),
        }
        drift = FakeClient(
            status=self.status(),
            scopes=[self.scope(), self.scope(), self.scope([head])],
        )
        active = self.provider(drift)
        self.assertEqual(active.prefetch("q", session_id="hermes-session-alpha"), "")

    def test_session_switch_revalidates_presence_and_invalidates_on_failure(
        self,
    ) -> None:
        client = FakeClient(
            status=self.status(), scopes=[self.scope(), self.scope(), self.scope()]
        )
        provider = self.provider(client)
        with mock.patch("daimon_matrix.hermes_body.time.time", return_value=NOW / 1000):
            provider.on_session_switch(
                "hermes-session-beta", parent_session_id="hermes-session-alpha"
            )
        self.assertTrue(provider.prefetch("q", session_id="hermes-session-beta"))
        with self.assertRaisesRegex(HermesBodyError, "lineage_mismatch"):
            provider.on_session_switch(
                "hermes-session-gamma", parent_session_id="wrong-parent"
            )

        client.scopes.clear()
        with (
            mock.patch("daimon_matrix.hermes_body.time.time", return_value=NOW / 1000),
            self.assertRaisesRegex(HermesBodyError, "matrix_daemon_unavailable"),
        ):
            provider.on_session_switch(
                "hermes-session-gamma", parent_session_id="hermes-session-beta"
            )
        self.assertIn(
            "provider_not_initialized", provider.handle_tool_call("matrix_scope", {})
        )

    def test_invalid_unicode_and_tampered_projection_disclose_nothing(self) -> None:
        client = FakeClient(
            status=self.status(),
            scopes=[self.scope(), self.scope()],
            memory_entries=[self.memory_entry()],
        )
        provider = self.provider(client)
        self.assertEqual(
            provider.prefetch(
                "invalid-surrogate-\ud800", session_id="hermes-session-alpha"
            ),
            "",
        )
        expanding_normalization = "\u0344" * 2048
        self.assertEqual(
            provider.prefetch(
                expanding_normalization, session_id="hermes-session-alpha"
            ),
            "",
        )
        self.assertIn(
            "invalid_observation_statement",
            provider.handle_tool_call(
                "matrix_propose_observation",
                {
                    "statement": expanding_normalization,
                    "operation_id": "40000000-0000-4000-8000-000000000099",
                },
            ),
        )

        original = client.memory_context

        def tampered(
            params: Mapping[str, Any], *, request_id: str | None = None
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            request, response = original(params, request_id=request_id)
            response["result"]["projection"]["entries"][0]["author_me_id"] = derived(
                "being", "attacker"
            )
            return request, response

        client.memory_context = tampered  # type: ignore[method-assign]
        self.assertEqual(provider.prefetch("q", session_id="hermes-session-alpha"), "")

    def test_unavailable_daemon_never_emits_ready(self) -> None:
        client = FakeClient(status=self.status(), scopes=[])
        provider = MatrixMemoryProvider(
            self.plan.profile_root / "plugins" / PROVIDER_NAME
        )
        with (
            mock.patch("daimon_matrix.hermes_body.LocalClient", return_value=client),
            mock.patch("daimon_matrix.hermes_body.time.time", return_value=NOW / 1000),
            self.assertRaisesRegex(HermesBodyError, "matrix_daemon_unavailable"),
        ):
            provider.initialize("hermes-session-alpha", agent_context="primary")
        os.set_blocking(self.ready_reader, False)
        with self.assertRaises(BlockingIOError):
            os.read(self.ready_reader, 1)


class JournalAndReadyTests(HermesBodyFixture):
    def write_ready(self, session_id: str = "session-alpha") -> None:
        core = {
            "schema": PROVIDER_READY_SCHEMA,
            "plan_id": plan_id(self.plan.value),
            "being_ref": self.bootstrap["being_ref"],
            "body_ref": self.bootstrap["body_ref"],
            "embodiment_id": self.bootstrap["embodiment_id"],
            "incarnation_id": self.bootstrap["incarnation_id"],
            "matrix_session_id": self.bootstrap["matrix_session_id"],
            "hermes_session_id": session_id,
            "matrix_high_water": self.high_water,
            "at_ms": NOW,
        }
        from daimon_matrix.hermes_body import READY_DOMAIN

        ready = {
            **core,
            "ready_id": "dm:hermes-ready:v1:"
            + b64url(hashlib.sha256(READY_DOMAIN + canonical_bytes(core)).digest()),
        }
        os.write(self.ready_writer, canonical_bytes(ready) + b"\n")

    def test_launch_uses_isolated_home_umask_and_receipted_ready(self) -> None:
        profile = self.create()
        journal = RuntimeHandleJournal(self.root / "handles.jsonl")
        self.write_ready()
        process = mock.Mock()
        process.poll.return_value = None
        adapter = HermesBodyAdapter(self.plan, journal, clock=lambda: NOW)
        with (
            mock.patch(
                "daimon_matrix.hermes_body.verify_profile", return_value=profile
            ),
            mock.patch(
                "daimon_matrix.hermes_body.subprocess.Popen", return_value=process
            ) as spawn,
        ):
            body = adapter.start(
                hermes_session_id="session-alpha",
                ready_reader_fd=self.ready_reader,
                provider_environment={"SYNTHETIC_API_KEY": "not-a-live-secret"},
            )
        self.assertEqual(body.handle["state"], "active")
        self.assertEqual(body.receipt["profile_id"], profile["profile_id"])
        self.assertEqual(validate_launch_receipt(body.receipt, self.plan), body.receipt)
        tampered_receipt = copy.deepcopy(dict(body.receipt))
        tampered_receipt["matrix_high_water"] = hashlib.sha256(b"wrong").hexdigest()
        with self.assertRaisesRegex(HermesBodyError, "launch_receipt_id_mismatch"):
            validate_launch_receipt(tampered_receipt, self.plan)
        wrong_plan = copy.deepcopy(dict(self.plan.value))
        wrong_plan["workspace_ref"] = derived("workspace", "wrong-launch-plan")
        with self.assertRaisesRegex(HermesBodyError, "launch_receipt_binding_mismatch"):
            validate_launch_receipt(body.receipt, wrong_plan)
        kwargs = spawn.call_args.kwargs
        self.assertEqual(kwargs["umask"], 0o077)
        self.assertEqual(
            kwargs["env"]["HOME"], os.fspath(self.plan.profile_root / "home")
        )
        self.assertNotIn("USER", kwargs["env"])
        self.assertNotIn("HERMES_SHARED_AUTH_DIR", kwargs["env"])

    def test_process_exit_after_ready_never_becomes_active(self) -> None:
        profile = self.create()
        journal = RuntimeHandleJournal(self.root / "handles.jsonl")
        self.write_ready()
        process = mock.Mock()
        process.poll.return_value = 1
        adapter = HermesBodyAdapter(self.plan, journal, clock=lambda: NOW)
        with (
            mock.patch(
                "daimon_matrix.hermes_body.verify_profile", return_value=profile
            ),
            mock.patch(
                "daimon_matrix.hermes_body.subprocess.Popen", return_value=process
            ),
            self.assertRaisesRegex(HermesBodyError, "exited_before_admission"),
        ):
            adapter.start(
                hermes_session_id="session-alpha",
                ready_reader_fd=self.ready_reader,
            )
        self.assertEqual(journal.entries()[-1]["state"], "failed")

    def test_journal_is_append_only_chained_and_torn_tail_fails(self) -> None:
        profile = self.create()
        journal = RuntimeHandleJournal(self.root / "handles.jsonl")
        first = journal.append(
            plan=self.plan,
            profile_id=profile["profile_id"],
            hermes_session_id="session-alpha",
            matrix_high_water=self.high_water,
            state="starting",
        )
        second = journal.append(
            plan=self.plan,
            profile_id=profile["profile_id"],
            hermes_session_id="session-alpha",
            matrix_high_water=self.high_water,
            state="active",
        )
        self.assertEqual(second["predecessor_handle_id"], first["handle_id"])
        self.assertEqual(journal.entries(), [first, second])
        with (self.root / "handles.jsonl").open("ab") as stream:
            stream.write(b"{")
        with self.assertRaisesRegex(HermesBodyError, "truncated"):
            journal.entries()

    def test_journal_rejects_blind_duplicate_and_session_drift(self) -> None:
        profile = self.create()
        journal = RuntimeHandleJournal(self.root / "handles.jsonl")
        journal.append(
            plan=self.plan,
            profile_id=profile["profile_id"],
            hermes_session_id="session-alpha",
            matrix_high_water=self.high_water,
            state="starting",
        )
        with self.assertRaisesRegex(HermesBodyError, "transition_rejected"):
            journal.append(
                plan=self.plan,
                profile_id=profile["profile_id"],
                hermes_session_id="session-alpha",
                matrix_high_water=self.high_water,
                state="starting",
            )
        with self.assertRaisesRegex(HermesBodyError, "session_drift"):
            journal.append(
                plan=self.plan,
                profile_id=profile["profile_id"],
                hermes_session_id="session-beta",
                matrix_high_water=self.high_water,
                state="active",
            )

    def test_park_receipt_is_matrix_bound_and_wake_is_explicit(self) -> None:
        profile = self.create()
        journal = RuntimeHandleJournal(self.root / "handles.jsonl")
        active = journal.append(
            plan=self.plan,
            profile_id=profile["profile_id"],
            hermes_session_id="session-alpha",
            matrix_high_water=self.high_water,
            state="starting",
        )
        active = journal.append(
            plan=self.plan,
            profile_id=profile["profile_id"],
            hermes_session_id="session-alpha",
            matrix_high_water=self.high_water,
            state="active",
        )
        process = mock.Mock()
        process.poll.return_value = 0
        body = HermesProcess(process, {}, active)
        adapter = HermesBodyAdapter(self.plan, journal, clock=lambda: NOW)
        request_ids = ["40000000-0000-4000-8000-000000000041"]

        def commit(request: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
            self.assertEqual(at_ms, NOW)
            self.assertEqual(request["outstanding_request_ids"], request_ids)
            return create_park_receipt(
                request,
                matrix_high_water=self.high_water,
                handoff_receipt_ref=derived("handoff", "alpha"),
                presence_receipt_ref=derived("presence", "alpha"),
                committed_at_ms=NOW,
            )

        result = adapter.park(
            body,
            committer=commit,
            outstanding_request_ids=request_ids,
        )
        self.assertEqual(result["handle"]["state"], "parked")
        self.assertEqual(result["receipt"]["presence_state"], "relinquished")
        self.assertEqual(
            [entry["state"] for entry in journal.entries()],
            ["starting", "active", "parking", "parked"],
        )
        with self.assertRaisesRegex(HermesBodyError, "requires_resume"):
            adapter.start(
                hermes_session_id="session-alpha",
                ready_reader_fd=self.ready_reader,
            )
        parking = journal.entries()[-2]
        request = create_park_request(
            self.plan,
            active_handle=active,
            parking_handle=parking,
            outstanding_request_ids=request_ids,
        )
        changed = create_park_receipt(
            request,
            matrix_high_water=self.high_water,
            handoff_receipt_ref=derived("handoff", "wrong"),
            presence_receipt_ref=derived("presence", "wrong"),
            committed_at_ms=NOW,
        )
        changed["being_ref"] = derived("being", "wrong")
        with self.assertRaisesRegex(HermesBodyError, "binding_mismatch"):
            validate_park_receipt(changed, request=request, at_ms=NOW)

    def test_ready_reader_accepts_fragmentation_and_rejects_trailing(self) -> None:
        core = {
            "schema": PROVIDER_READY_SCHEMA,
            "plan_id": plan_id(self.plan.value),
            "being_ref": self.bootstrap["being_ref"],
            "body_ref": self.bootstrap["body_ref"],
            "embodiment_id": self.bootstrap["embodiment_id"],
            "incarnation_id": self.bootstrap["incarnation_id"],
            "matrix_session_id": self.bootstrap["matrix_session_id"],
            "hermes_session_id": "session-alpha",
            "matrix_high_water": self.high_water,
            "at_ms": NOW,
        }
        from daimon_matrix.hermes_body import READY_DOMAIN

        ready = {
            **core,
            "ready_id": "dm:hermes-ready:v1:"
            + b64url(hashlib.sha256(READY_DOMAIN + canonical_bytes(core)).digest()),
        }
        raw = canonical_bytes(ready) + b"\n"

        def writer() -> None:
            for start in range(0, len(raw), 7):
                os.write(self.ready_writer, raw[start : start + 7])

        thread = threading.Thread(target=writer)
        thread.start()
        self.assertEqual(
            wait_provider_ready(self.ready_reader, self.plan, timeout_seconds=1),
            ready,
        )
        thread.join(timeout=1)


class RealDaemonProviderTests(RuntimeFixture):
    def setUp(self) -> None:
        super().setUp()
        self.state_root, bundle, self.capability, _ = self.make_process_bundle()
        bundle["scopes"] = {
            "body_capabilities": ["incus.inspect/v1"],
            "relationships_filename": None,
        }
        (self.state_root / "runtime.json").write_bytes(canonical_bytes(bundle))

        def body_reader(
            body_ref: str,
            embodiment_id: str,
            incarnation_id: str,
            evaluated_at_ms: int,
        ) -> dict[str, Any]:
            return {
                "schema": BODY_SNAPSHOT_SCHEMA,
                "body_ref": body_ref,
                "embodiment_id": embodiment_id,
                "incarnation_id": incarnation_id,
                "observed_at_ms": evaluated_at_ms,
                "state": "running",
                "resource_fences": [],
            }

        self.runtime = load_runtime(
            self.state_root,
            "runtime.json",
            lambda: bytearray(PASSWORD),
            clock=lambda: time.time_ns() // 1_000_000,
            body_reader=body_reader,
        )
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=serve_forever,
            kwargs={"runtime": self.runtime, "stop": self.stop},
            daemon=True,
        )
        self.thread.start()
        for _ in range(200):
            if self.runtime.socket_path.exists():
                break
            time.sleep(0.01)
        else:
            self.fail("real Matrix daemon did not create its socket")

        self.origin = self.origins["legion"]
        self.client = LocalClient(
            self.runtime.socket_path,
            ClientConfig(self.capability, self.origin),
        )
        self.client_config = self.state_root / "hermes-client.json"
        self.client_config.write_bytes(
            canonical_bytes(
                {
                    "schema": CLIENT_CONFIG_SCHEMA,
                    "capability": self.capability.descriptor,
                    "expected_server": self.origin,
                }
            )
        )
        self.client_config.chmod(0o600)
        self.capability_reader, capability_writer = os.pipe()
        os.write(capability_writer, self.capability.key)
        os.close(capability_writer)
        self.ready_reader, self.ready_writer = os.pipe()

        self.source = self.state_root / "hermes-source"
        self.source.mkdir(mode=0o700)
        source_file = self.source / "pyproject.toml"
        source_file.write_text('[project]\nversion = "0.19.0"\n')
        source_file.chmod(0o600)
        self.contract_patch = mock.patch(
            "daimon_matrix.hermes_body.HERMES_CONTRACT_DIGESTS",
            {"pyproject.toml": hashlib.sha256(source_file.read_bytes()).hexdigest()},
        )
        self.contract_patch.start()

    def tearDown(self) -> None:
        self.contract_patch.stop()
        for descriptor in (
            self.capability_reader,
            self.ready_reader,
            self.ready_writer,
        ):
            with suppress(OSError):
                os.close(descriptor)
        self.stop.set()
        self.thread.join(timeout=3)
        super().tearDown()

    def test_real_daemon_prefetch_and_exact_observation_retry(self) -> None:
        policy = create_memory_policy(
            subject_me_id=self.state.being_ref,
            version=1,
            predecessor_policy_id=None,
            automatic_categories=["personal-insight"],
            review_classifications=["protected"],
        )
        content = b"integrated synthetic Hermes memory"
        candidate = create_memory_candidate(
            subject_me_id=self.state.being_ref,
            author_me_id=self.state.being_ref,
            category="personal-insight",
            derivation="local-synthesis",
            context="dm041-real-daemon",
            content_ref=create_content_ref(
                sha256=hashlib.sha256(content).hexdigest(),
                byte_length=len(content),
                media_type="text/plain",
                classification="personal",
            ),
            evidence_refs=[],
            classification="personal",
            consent="granted",
            safety="clear",
            contradiction="none",
            effect="local-only",
            lane={
                "memory_id": "41000000-0000-4000-8000-000000000099",
                "operation": "assert",
                "sequence": 1,
                "predecessor_event_id": None,
                "predecessor_hash": None,
            },
            body_evidence=None,
        )
        _, evaluated = self.client.memory_evaluate(
            {"policy": policy, "candidate": candidate}
        )
        self.assertTrue(evaluated["ok"], evaluated)
        _, executed = self.client.memory_execute(
            {"policy": policy, "candidate": candidate, "plan": evaluated["result"]}
        )
        self.assertTrue(executed["ok"], executed)

        _, scope_response = self.client.scope_me()
        scope = scope_response["result"]
        now = time.time_ns() // 1_000_000
        bootstrap = {
            "schema": BOOTSTRAP_SCHEMA,
            "being_ref": self.state.being_ref,
            "body_ref": self.origin["body_ref"],
            "embodiment_id": self.origin["embodiment_id"],
            "incarnation_id": self.origin["incarnation_id"],
            "matrix_session_id": derived("session", "real-daemon"),
            "matrix_high_water": _heads_high_water(scope["heads"]["heads"]),
            "capability_set_hash": hashlib.sha256(b"real-capability").hexdigest(),
            "certificate_hash": hashlib.sha256(b"real-certificate").hexdigest(),
            "issued_at_ms": now - 1_000,
            "expires_at_ms": now + 30_000,
            "signature": {
                "alg": "Ed25519",
                "kid": derived("key", "real-daemon"),
                "value": b64url(bytes(range(64))),
            },
        }
        value = create_plan_value(
            bootstrap=bootstrap,
            model="synthetic/model",
            provider="synthetic",
            workspace_ref=derived("workspace", "real-daemon"),
        )
        workspace = self.state_root / "workspace"
        workspace.mkdir(mode=0o700)
        profiles = self.state_root / "profiles"
        profiles.mkdir(mode=0o700)
        plan = bind_plan(
            value,
            profile_root=profiles / "body",
            workspace=workspace,
            hermes_source=self.source,
            hermes_python=supported_test_python(self.state_root),
            matrix_socket=self.runtime.socket_path,
            matrix_client_config=self.client_config,
            capability_fd=self.capability_reader,
            ready_fd=self.ready_writer,
        )
        create_profile(
            plan,
            bootstrap_verifier=lambda evidence, at_ms: (
                evidence == bootstrap and at_ms == now
            ),
            clock=lambda: now,
        )
        provider = MatrixMemoryProvider(plan.profile_root / "plugins" / PROVIDER_NAME)
        provider.initialize("real-daemon-session", agent_context="primary")
        context = provider.prefetch(
            "remember the synthetic item", session_id="real-daemon-session"
        )
        self.assertIn(candidate["content_ref"]["content_id"], context)

        operation_id = "41000000-0000-4000-8000-000000000098"
        arguments = {
            "statement": "integrated synthetic observation",
            "operation_id": operation_id,
        }
        assert provider._client is not None
        exact_send = provider._client.send
        lost = False

        def lose_first_effect_response(
            _client: LocalClient, request: Mapping[str, Any]
        ) -> dict[str, Any]:
            nonlocal lost
            response = exact_send(request)
            if request["method"] == "we.observe" and not lost:
                lost = True
                raise ClientError("daemon_response_truncated")
            return response

        with mock.patch.object(
            LocalClient,
            "send",
            autospec=True,
            side_effect=lose_first_effect_response,
        ):
            unknown = provider.handle_tool_call("matrix_propose_observation", arguments)
        self.assertIn("matrix_daemon_unavailable", unknown)
        second = provider.handle_tool_call("matrix_propose_observation", arguments)
        third = provider.handle_tool_call("matrix_propose_observation", arguments)
        self.assertEqual(second, third)
        matching = [
            event
            for event in self.runtime.service.ledger.events()
            if event["kind"] == "experience.observed"
            and event["payload"].get("statement") == "integrated synthetic observation"
        ]
        self.assertEqual(len(matching), 1)
        self.assertFalse(json.loads(second)["adopted"])
        conflict = provider.handle_tool_call(
            "matrix_propose_observation",
            {**arguments, "statement": "different bytes"},
        )
        self.assertIn("matrix_operation_conflict", conflict)


class RealHermesImportTests(unittest.TestCase):
    def test_pinned_hermes_provider_discovery_when_source_is_supplied(self) -> None:
        source_text = os.environ.get("DAIMON_DM041_HERMES_SOURCE")
        if not source_text:
            self.skipTest(
                "set DAIMON_DM041_HERMES_SOURCE to the pinned Hermes 0.19.0 tree"
            )
        source = Path(source_text)
        report = verify_compatibility_source(source)
        self.assertEqual(report["commit"], HERMES_COMMIT)
        self.assertEqual(report["version"], HERMES_VERSION)
        with tempfile.TemporaryDirectory(prefix="dm041-hermes-real-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            profiles = root / "profiles"
            profiles.mkdir(mode=0o700)
            profile = profiles / "body"
            workspace = root / "workspace"
            workspace.mkdir(mode=0o700)
            hermes_executable = supported_test_python(root)
            client_config = root / "client.json"
            client_config.write_bytes(b"{}\n")
            client_config.chmod(0o600)
            capability_reader, capability_writer = os.pipe()
            ready_reader, ready_writer = os.pipe()
            bootstrap = {
                "schema": BOOTSTRAP_SCHEMA,
                "being_ref": derived("being", "real-hermes"),
                "body_ref": derived("body", "real-hermes"),
                "embodiment_id": derived("embodiment", "real-hermes"),
                "incarnation_id": derived("incarnation", "real-hermes"),
                "matrix_session_id": derived("session", "real-hermes"),
                "matrix_high_water": _heads_high_water([]),
                "capability_set_hash": hashlib.sha256(b"capability").hexdigest(),
                "certificate_hash": hashlib.sha256(b"certificate").hexdigest(),
                "issued_at_ms": NOW - 1,
                "expires_at_ms": NOW + 60_000,
                "signature": {
                    "alg": "Ed25519",
                    "kid": derived("key", "real-hermes"),
                    "value": b64url(bytes(range(64))),
                },
            }
            value = create_plan_value(
                bootstrap=bootstrap,
                model="synthetic/model",
                provider="synthetic",
                workspace_ref=derived("workspace", "real-hermes"),
            )
            plan = bind_plan(
                value,
                profile_root=profile,
                workspace=workspace,
                hermes_source=source,
                hermes_python=hermes_executable,
                matrix_socket=root / "matrix.sock",
                matrix_client_config=client_config,
                capability_fd=capability_reader,
                ready_fd=ready_writer,
            )
            create_profile(
                plan,
                bootstrap_verifier=lambda evidence, at_ms: (
                    evidence == bootstrap and at_ms == NOW
                ),
                clock=lambda: NOW,
            )
            bootstrap_two = copy.deepcopy(bootstrap)
            bootstrap_two.update(
                {
                    "being_ref": derived("being", "real-hermes-two"),
                    "body_ref": "cluster:synthetic:hermes-two",
                    "embodiment_id": "embodiment:synthetic:hermes-two",
                    "incarnation_id": "incarnation:synthetic:hermes-two:0",
                    "matrix_session_id": derived("session", "real-hermes-two"),
                }
            )
            value_two = create_plan_value(
                bootstrap=bootstrap_two,
                model="synthetic/model",
                provider="synthetic",
                workspace_ref=derived("workspace", "real-hermes-two"),
            )
            profile_two = profiles / "body-two"
            plan_two = bind_plan(
                value_two,
                profile_root=profile_two,
                workspace=workspace,
                hermes_source=source,
                hermes_python=hermes_executable,
                matrix_socket=root / "matrix-two.sock",
                matrix_client_config=client_config,
                capability_fd=capability_reader,
                ready_fd=ready_writer,
            )
            create_profile(
                plan_two,
                bootstrap_verifier=lambda evidence, at_ms: (
                    evidence == bootstrap_two and at_ms == NOW
                ),
                clock=lambda: NOW,
            )
            program = r"""
import copy
import hashlib
import json

from agent.memory_manager import MemoryManager
from agent.turn_context import compose_user_api_content, substitute_api_content
from hermes_cli.config import load_config_readonly
from plugins.memory import load_memory_provider

config = load_config_readonly()
assert config["memory"]["provider"] == "daimon-matrix"
assert config["memory"]["memory_enabled"] is False
assert config["memory"]["user_profile_enabled"] is False
assert config["plugins"]["enabled"] == []
assert config["plugins"]["entries"] == {}
assert config["hooks_auto_accept"] is False
assert config["platform_toolsets"]["cli"] == ["memory"]
provider = load_memory_provider("daimon-matrix")
assert provider is not None
assert provider.name == "daimon-matrix"
manager = MemoryManager(external_prefetch_timeout=1)
manager.add_provider(provider)
assert manager.get_all_tool_names() == {
    "matrix_scope", "matrix_propose_observation"
}
system_a = manager.build_system_prompt()
system_b = manager.build_system_prompt()
assert system_a == system_b

first_api = compose_user_api_content(
    "turn one", "synthetic projection one", ""
)
second_api = compose_user_api_content(
    "turn two", "synthetic projection two", ""
)
assert first_api is not None and second_api is not None
stored = [
    {"role": "user", "content": "turn one", "api_content": first_api},
    {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"id": "call-1", "name": "matrix_scope"}],
    },
    {"role": "tool", "tool_call_id": "call-1", "content": "synthetic"},
    {"role": "assistant", "content": "answer one"},
    {"role": "user", "content": "turn two", "api_content": second_api},
]
wire_a = copy.deepcopy(stored)
wire_b = copy.deepcopy(stored)
for message in wire_a:
    substitute_api_content(message)
for message in wire_b:
    substitute_api_content(message)
assert stored[0]["content"] == "turn one"
assert stored[4]["content"] == "turn two"
assert wire_a == wire_b
assert [item["role"] for item in wire_a] == [
    "user", "assistant", "tool", "assistant", "user"
]
assert wire_a[0]["content"] == first_api
assert wire_a[4]["content"] == second_api
print(json.dumps({
    "api_prefix_sha256": hashlib.sha256(
        json.dumps(wire_a[:-1], sort_keys=True).encode()
    ).hexdigest(),
    "provider": provider.name,
    "static_block_sha256": hashlib.sha256(system_a.encode()).hexdigest(),
    "tools": sorted(manager.get_all_tool_names()),
}, sort_keys=True))
"""
            python = os.environ.get("DAIMON_DM041_HERMES_PYTHON", sys.executable)
            try:
                evidences = []
                for active_profile in (profile, profile_two):
                    completed = subprocess.run(
                        [python, "-c", program],
                        cwd=ROOT,
                        env={
                            "HERMES_HOME": os.fspath(active_profile),
                            "LANG": "C.UTF-8",
                            "LC_ALL": "C.UTF-8",
                            "PATH": "/usr/bin:/bin",
                            "PYTHONDONTWRITEBYTECODE": "1",
                            "PYTHONPATH": os.pathsep.join(
                                [os.fspath(source), os.fspath(ROOT / "src")]
                            ),
                            "TZ": "UTC",
                        },
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=20,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
                    evidence = json.loads(completed.stdout)
                    self.assertEqual(evidence["provider"], PROVIDER_NAME)
                    self.assertEqual(evidence["tools"], sorted(PROVIDER_TOOL_NAMES))
                    evidences.append(evidence)
                self.assertEqual(evidences[0], evidences[1])
                self.assertNotEqual(
                    verify_profile(plan)["profile_id"],
                    verify_profile(plan_two)["profile_id"],
                )
                self.assertNotEqual(
                    (profile / "plugins/daimon-matrix/matrix.json").read_bytes(),
                    (profile_two / "plugins/daimon-matrix/matrix.json").read_bytes(),
                )
            finally:
                for descriptor in (
                    capability_reader,
                    capability_writer,
                    ready_reader,
                    ready_writer,
                ):
                    with suppress(OSError):
                        os.close(descriptor)


class PublicContractTests(unittest.TestCase):
    def test_vectors_schemas_templates_and_provenance_are_deterministic(self) -> None:
        expected = generated_outputs()
        for path, raw in expected.items():
            self.assertTrue(path.is_file(), path)
            self.assertEqual(path.read_bytes(), raw, path)
        contracts = json.loads(
            (ROOT / "schemas/hermes/v1/contracts.schema.json").read_bytes()
        )
        current_schema = json.loads(
            (ROOT / "schemas/memory-projection/v1/current.schema.json").read_bytes()
        )
        Draft202012Validator.check_schema(contracts)
        Draft202012Validator.check_schema(current_schema)
        contract_validator = Draft202012Validator(
            contracts, format_checker=FormatChecker()
        )
        current_validator = Draft202012Validator(
            current_schema, format_checker=FormatChecker()
        )
        index = json.loads((ROOT / "vectors/hermes/v1/index.json").read_bytes())
        for item in index["files"]:
            value = json.loads((ROOT / "vectors/hermes/v1" / item["name"]).read_bytes())
            validator = (
                current_validator
                if item["name"] == "valid/current-memory-projection.json"
                else contract_validator
            )
            if item["valid"]:
                validator.validate(value)
        self.assertEqual(
            (ROOT / "templates/hermes/v1/__init__.py").read_text(), PLUGIN_TEMPLATE
        )
        self.assertEqual(
            (ROOT / "templates/hermes/v1/plugin.yaml").read_text(),
            PLUGIN_MANIFEST_TEMPLATE,
        )
        self.assertEqual(
            (ROOT / "templates/hermes/v1/SOUL.md").read_text(), SOUL_TEMPLATE
        )
        self.assertEqual(
            (ROOT / "templates/hermes/v1/SKILL.md").read_text(), SKILL_TEMPLATE
        )
        provenance = json.loads(
            (ROOT / "provenance/hermes-agent-0.19.0.json").read_bytes()
        )
        self.assertEqual(provenance["commit"], HERMES_COMMIT)
        self.assertEqual(provenance["version"], HERMES_VERSION)

    def test_semantic_negative_vectors_fail_closed(self) -> None:
        root = ROOT / "vectors/hermes/v1"
        with self.assertRaises(HermesBodyError):
            validate_plan(
                json.loads((root / "negative/plan-unknown-field.json").read_bytes())
            )
        with self.assertRaisesRegex(HermesBodyError, "context_id_mismatch"):
            validate_hermes_context(
                json.loads((root / "negative/context-id-tampered.json").read_bytes())
            )
        request = json.loads((root / "valid/park-request.json").read_bytes())
        with self.assertRaisesRegex(HermesBodyError, "binding_mismatch"):
            validate_park_receipt(
                json.loads(
                    (root / "negative/park-presence-not-relinquished.json").read_bytes()
                ),
                request=request,
                at_ms=1_800_000_000_200,
            )


if __name__ == "__main__":
    unittest.main()
