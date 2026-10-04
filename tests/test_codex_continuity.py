"""Real private profile I/O for explicit SOUL/foundation/memory continuity."""

from __future__ import annotations

import copy
import hashlib
import os
import unittest
from dataclasses import replace
from typing import Any

from daimon_matrix import codex_body as body
from tests import test_codex_0155_body as fixtures


class ContinuityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.SuccessorProfileTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source = self.fixture.root / "continuity"
        self.source.mkdir(mode=0o700)
        self.payloads = {
            "SOUL.md": b"# CompAII\nHermes origin; evolving as the same being.\n",
            "FOUNDATION.md": b"/me.memory\n/we\n",
            "MEMORY-ACCESS.md": (
                b"Only on human request: /selected/bin/hmk memoryctl.py hybrid-pack\n"
            ),
        }
        self.selection: dict[str, Any] = {
            "schema": "dm.codex-continuity/v1",
            "files": {
                name: {
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "source_ref": "owner-selected:" + name,
                }
                for name, raw in self.payloads.items()
            },
        }
        for name, raw in self.payloads.items():
            (self.source / name).write_bytes(raw)
            (self.source / name).chmod(0o600)
        self.plan = replace(
            self.fixture.plan,
            value={**self.fixture.value, "continuity": self.selection},
            continuity_source=self.source,
        )

    def create(self) -> dict[str, Any]:
        return body.create_profile(
            self.plan,
            bootstrap_verifier=lambda value, now: True,
            clock=lambda: self.fixture.now,
        )

    def test_exact_context_is_loaded_and_manifest_bound(self) -> None:
        manifest = self.create()
        agents = (self.plan.profile_root / "AGENTS.md").read_bytes()
        for name, raw in self.payloads.items():
            self.assertIn(raw, agents)
            self.assertEqual((self.plan.profile_root / name).read_bytes(), raw)
            self.assertEqual(
                (self.plan.profile_root / name).stat().st_mode & 0o777, 0o600
            )
            self.assertIn(
                {"name": name, "sha256": hashlib.sha256(raw).hexdigest()},
                manifest["files"],
            )
        self.assertIn(b"Do not prefetch on startup", agents)
        self.assertEqual(body.verify_profile(self.plan), manifest)
        config = (self.plan.profile_root / "config.toml").read_text()
        self.assertIn("project_doc_max_bytes = 32768", config)
        self.assertLessEqual(len(agents), 32768)

    def test_resume_uses_private_selected_copy_not_original(self) -> None:
        manifest = self.create()
        (self.source / "SOUL.md").write_bytes(b"Later source evolution\n")
        resumed = replace(self.plan, continuity_source=None)
        self.assertEqual(body.verify_profile(resumed), manifest)
        (resumed.profile_root / "SOUL.md").write_bytes(b"Unselected local edit\n")
        with self.assertRaisesRegex(body.CodexBodyError, "codex_continuity_file_drift"):
            body.verify_profile(resumed)

    def test_selected_skills_and_continuity_share_verified_profile(self) -> None:
        selected = self.fixture.selected_skills()
        self.plan = replace(
            selected,
            value={**selected.value, "continuity": self.selection},
            continuity_source=self.source,
        )
        manifest = self.create()
        names = {entry["name"] for entry in manifest["files"]}
        self.assertTrue(set(body.CONTINUITY_NAMES) <= names)
        self.assertTrue(any(name.startswith(".agents/skills/") for name in names))
        self.assertEqual(body.verify_profile(self.plan), manifest)

    def test_source_drift_refuses_before_creating_profile(self) -> None:
        (self.source / "SOUL.md").write_bytes(b"Changed source\n")
        with self.assertRaisesRegex(body.CodexBodyError, "codex_continuity_file_drift"):
            self.create()
        self.assertFalse(self.plan.profile_root.exists())

    def test_missing_selection_source_refuses_before_creation(self) -> None:
        self.plan = replace(self.plan, continuity_source=None)
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_source_required"
        ):
            self.create()
        self.assertFalse(self.plan.profile_root.exists())

    def test_link_and_public_source_refused(self) -> None:
        soul = self.source / "SOUL.md"
        soul.chmod(0o644)
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_file_rejected"
        ):
            self.create()
        soul.chmod(0o600)
        saved = self.source / "original"
        soul.rename(saved)
        soul.symlink_to(saved)
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_file_rejected"
        ):
            self.create()
        self.assertFalse(self.plan.profile_root.exists())

    def test_hard_link_and_executable_source_refused(self) -> None:
        soul = self.source / "SOUL.md"
        soul.chmod(0o700)
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_file_rejected"
        ):
            self.create()
        soul.chmod(0o600)
        os.link(soul, self.source / "alias")
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_file_rejected"
        ):
            self.create()

    def test_invalid_utf8_and_nul_refused(self) -> None:
        for raw in (b"bad\xff", b"bad\x00"):
            with self.subTest(raw=raw):
                (self.source / "SOUL.md").write_bytes(raw)
                self.selection["files"]["SOUL.md"].update(
                    bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
                )
                with self.assertRaisesRegex(
                    body.CodexBodyError, "codex_continuity_text_rejected"
                ):
                    self.create()
                self.assertFalse(self.plan.profile_root.exists())

    def test_instruction_limit_refuses_truncation(self) -> None:
        for name in ("SOUL.md", "FOUNDATION.md"):
            raw = b"a" * 24000
            (self.source / name).write_bytes(raw)
            self.selection["files"][name].update(
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
            )
        with self.assertRaisesRegex(
            body.CodexBodyError, "codex_continuity_instruction_limit"
        ):
            self.create()
        self.assertFalse(self.plan.profile_root.exists())

    def test_selection_closed_and_historical_forbidden(self) -> None:
        for mutate in ("extra", "missing", "zero", "secret"):
            selection = copy.deepcopy(self.selection)
            if mutate == "extra":
                selection["automatic_prefetch"] = True
            elif mutate == "missing":
                del selection["files"]["SOUL.md"]
            elif mutate == "zero":
                selection["files"]["SOUL.md"]["bytes"] = 0
            else:
                selection["files"]["SOUL.md"]["content"] = "private"
            with self.subTest(mutate=mutate), self.assertRaises(body.CodexBodyError):
                body.validate_continuity(selection)
        historical = body.create_plan_value(
            bootstrap=self.fixture.bootstrap,
            model="probe",
            provider="probe",
            workspace_ref=self.fixture.value["workspace_ref"],
        )
        with self.assertRaisesRegex(
            body.CodexBodyError, "historical_codex_continuity_forbidden"
        ):
            body.validate_plan({**historical, "continuity": self.selection})

    def test_no_selection_retains_original_instruction_bytes(self) -> None:
        body.create_profile(
            self.fixture.plan,
            bootstrap_verifier=lambda value, now: True,
            clock=lambda: self.fixture.now,
        )
        self.assertEqual(
            (self.fixture.plan.profile_root / "AGENTS.md").read_bytes(),
            body.SUCCESSOR_AGENTS_TEMPLATE.encode(),
        )
        self.assertFalse((self.fixture.plan.profile_root / "SOUL.md").exists())


if __name__ == "__main__":
    unittest.main()
