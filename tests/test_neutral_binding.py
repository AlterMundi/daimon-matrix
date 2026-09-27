"""The neutral territory binding is derived, deterministic and fail-closed."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from daimon_matrix.neutral_binding import (
    ARTIFACT_FILENAMES,
    BINDING_SCHEMA,
    MANIFEST_SCHEMA,
    NeutralBindingError,
    binding_artifacts,
    main,
    plan_from_mapping,
    render_binding_manifest,
    render_env_fragment,
    render_hermes_skills_fragment,
    render_service_env,
    render_surface_check,
)

HOME = "/home/testowner"
MEMORY_BASE = HOME + "/.agents/memory/compaii/agent-memory"
SKILLS_ROOT = HOME + "/.agents/skills"


def plan_value(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": BINDING_SCHEMA,
        "being_name": "compaii",
        "host_word": "legion",
        "home": HOME,
        "platform": "linux-systemd",
        "harnesses": ["hermes", "codex"],
        "env_file": HOME + "/.hermes/.env",
        "wrapper_path": HOME + "/.local/bin/hmk",
        "service_unit": "hermes-gateway.service",
    }
    value.update(overrides)
    return value


def plan_value_no_unit(**overrides: Any) -> dict[str, Any]:
    value = plan_value(**overrides)
    del value["service_unit"]
    return value


def assert_code(test: unittest.TestCase, value: Any, code: str) -> None:
    with test.assertRaises(NeutralBindingError) as caught:
        plan_from_mapping(value)
    test.assertEqual(str(caught.exception), code)


class PlanValidationTests(unittest.TestCase):
    def test_valid_plan_derives_every_path(self) -> None:
        plan = plan_from_mapping(plan_value())
        self.assertEqual(plan.memory_base, MEMORY_BASE)
        self.assertEqual(plan.skills_root, SKILLS_ROOT)
        self.assertEqual(plan.agents_root, HOME + "/.agents")
        self.assertEqual(plan.memory_root, HOME + "/.agents/memory")
        self.assertEqual(plan.harnesses, ("hermes", "codex"))
        self.assertEqual(plan.service_unit, "hermes-gateway.service")

    def test_platform_field_sets_are_closed(self) -> None:
        value = plan_value(platform="env-file")
        del value["service_unit"]
        self.assertEqual(plan_from_mapping(value).service_unit, None)
        assert_code(self, plan_value(platform="env-file"), "invalid_binding_plan")
        assert_code(
            self, plan_value_no_unit(harnesses=["codex"]), "invalid_binding_plan"
        )

    def test_schema_must_match(self) -> None:
        assert_code(
            self,
            plan_value(schema="dm.neutral-binding/v0"),
            "unsupported_binding_schema",
        )
        assert_code(self, ["not", "a", "plan"], "invalid_binding_plan")

    def test_identity_and_path_fields_fail_closed(self) -> None:
        assert_code(self, plan_value(being_name="CompAII"), "invalid_being_name")
        assert_code(self, plan_value(being_name=""), "invalid_being_name")
        assert_code(self, plan_value(host_word="LEGION"), "invalid_host_word")
        assert_code(self, plan_value(home="relative/path"), "invalid_home")
        assert_code(self, plan_value(home="/"), "invalid_home")
        assert_code(self, plan_value(home="/a/"), "invalid_home")
        assert_code(self, plan_value(platform="windows"), "invalid_platform")
        assert_code(self, plan_value(service_unit="gateway"), "invalid_service_unit")
        assert_code(self, plan_value(env_file="/etc/hermes.env"), "invalid_env_file")
        assert_code(
            self, plan_value(wrapper_path="/usr/bin/hmk"), "invalid_wrapper_path"
        )

    def test_harnesses_fail_closed(self) -> None:
        assert_code(self, plan_value(harnesses=[]), "invalid_harnesses")
        assert_code(self, plan_value(harnesses=["codex", "codex"]), "invalid_harnesses")
        assert_code(self, plan_value(harnesses=["goose"]), "invalid_harnesses")
        assert_code(self, plan_value(harnesses="hermes"), "invalid_harnesses")


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = plan_from_mapping(plan_value())

    def test_rendering_is_deterministic(self) -> None:
        first = binding_artifacts(self.plan)
        second = binding_artifacts(self.plan)
        self.assertEqual(first, second)
        self.assertEqual(
            render_binding_manifest(self.plan), render_binding_manifest(self.plan)
        )

    def test_env_fragment_is_exact(self) -> None:
        expected = (
            f"HMK_AGENT_MEMORY_BASE={MEMORY_BASE}\n"
            f"HERMES_AGENT_MEMORY_BASE={MEMORY_BASE}\n"
        ).encode()
        self.assertEqual(render_env_fragment(self.plan), expected)

    def test_service_env_follows_platform(self) -> None:
        linux = render_service_env(self.plan)
        self.assertIn(b"[Service]", linux)
        self.assertIn(
            f'Environment="HMK_AGENT_MEMORY_BASE={MEMORY_BASE}"'.encode(), linux
        )
        macos = plan_from_mapping(plan_value_no_unit(platform="macos-launchagent"))
        plist = render_service_env(macos)
        self.assertIn(b"<key>EnvironmentVariables</key>", plist)
        self.assertIn(f"<string>{MEMORY_BASE}</string>".encode(), plist)
        fallback = plan_from_mapping(plan_value_no_unit(platform="env-file"))
        self.assertEqual(render_service_env(fallback), render_env_fragment(fallback))

    def test_hermes_fragment_requires_hermes(self) -> None:
        fragment = render_hermes_skills_fragment(self.plan)
        self.assertEqual(
            fragment,
            f"skills:\n  external_dirs:\n    - {SKILLS_ROOT}\n".encode(),
        )
        codex_only = plan_from_mapping(
            plan_value_no_unit(harnesses=["codex"], platform="env-file")
        )
        with self.assertRaises(NeutralBindingError) as caught:
            render_hermes_skills_fragment(codex_only)
        self.assertEqual(str(caught.exception), "hermes_not_in_binding")
        self.assertNotIn("hermes_skills_fragment", binding_artifacts(codex_only))

    def test_manifest_is_content_addressed(self) -> None:
        manifest = json.loads(render_binding_manifest(self.plan))
        self.assertEqual(manifest["schema"], MANIFEST_SCHEMA)
        self.assertEqual(manifest["being_name"], "compaii")
        self.assertEqual(manifest["paths"]["memory_base"], MEMORY_BASE)
        self.assertEqual(manifest["paths"]["service_unit"], "hermes-gateway.service")
        artifacts = binding_artifacts(self.plan)
        self.assertEqual(set(manifest["artifacts"]), set(artifacts))
        for name, data in artifacts.items():
            self.assertEqual(
                manifest["artifacts"][name], hashlib.sha256(data).hexdigest()
            )
        macos = plan_from_mapping(plan_value_no_unit(platform="macos-launchagent"))
        macos_manifest = json.loads(render_binding_manifest(macos))
        self.assertNotIn("service_unit", macos_manifest["paths"])


GOOD_SKILL = "---\nname: good-skill\ndescription: A valid shared skill.\n---\n\nBody.\n"
NESTED_SKILL = "---\nname: nested-skill\ndescription: Category layout.\n---\n\nBody.\n"


def build_territory(home: Path) -> None:
    (home / ".agents/skills/good-skill").mkdir(parents=True)
    (home / ".agents/skills/good-skill/SKILL.md").write_text(GOOD_SKILL)
    (home / ".agents/skills/tooling/nested-skill").mkdir(parents=True)
    (home / ".agents/skills/tooling/nested-skill/SKILL.md").write_text(NESTED_SKILL)
    memory = home / ".agents/memory/compaii/agent-memory"
    memory.mkdir(parents=True)
    (memory / "library.db").write_bytes(b"")
    (home / ".hermes").mkdir(parents=True)
    (home / ".hermes/.env").write_text(
        "SOME_OTHER=1\n"
        f"HMK_AGENT_MEMORY_BASE={memory}\n"
        f"HERMES_AGENT_MEMORY_BASE={memory}\n"
    )
    (home / ".hermes/config.yaml").write_text(
        f"skills:\n  external_dirs:\n    - {home}/.agents/skills\n"
    )
    (home / ".local/bin").mkdir(parents=True)
    wrapper = home / ".local/bin/hmk"
    wrapper.write_text("#!/bin/sh\nexit 0\n")
    wrapper.chmod(0o755)


class SurfaceCheckTests(unittest.TestCase):
    def run_check(self, home: Path) -> subprocess.CompletedProcess[str]:
        plan = plan_from_mapping(
            plan_value(
                home=str(home),
                env_file=str(home / ".hermes/.env"),
                wrapper_path=str(home / ".local/bin/hmk"),
            )
        )
        script = home / "surface_check.py"
        script.write_bytes(render_surface_check(plan))
        return subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_clean_territory_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            build_territory(home)
            result = self.run_check(home)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("surface-check: ok", result.stdout)
            self.assertIn("PASS skill-frontmatter:good-skill", result.stdout)
            self.assertIn("PASS skill-frontmatter:nested-skill", result.stdout)
            self.assertIn("PASS hermes-external-skills-root-configured", result.stdout)

    def test_tilde_form_external_dirs_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            build_territory(home)
            (home / ".hermes/config.yaml").write_text(
                "skills:\n  external_dirs:\n    - ~/.agents/skills\n"
            )
            result = self.run_check(home)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS hermes-external-skills-root-configured", result.stdout)

    def test_every_drift_fails_loud(self) -> None:
        cases: dict[str, Callable[[Path], object]] = {
            "skill-frontmatter:good-skill": lambda home: (
                home / ".agents/skills/good-skill/SKILL.md"
            ).write_text("---\nname: good-skill\n---\n\nNo description.\n"),
            "skill-directory-without-skill:empty-dir": lambda home: (
                home / ".agents/skills/empty-dir"
            ).mkdir(),
            "env-line:HMK_AGENT_MEMORY_BASE": lambda home: (
                home / ".hermes/.env"
            ).write_text("HMK_AGENT_MEMORY_BASE=/somewhere/else\n"),
            "memory-library-db-present": lambda home: (
                home / ".agents/memory/compaii/agent-memory/library.db"
            ).unlink(),
            "hermes-external-skills-root-configured": lambda home: (
                home / ".hermes/config.yaml"
            ).write_text("skills:\n  external_dirs: []\n"),
            "wrapper-executable": lambda home: (home / ".local/bin/hmk").chmod(0o644),
        }
        for expected, mutate in cases.items():
            with self.subTest(failure=expected), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp) / "home"
                home.mkdir()
                build_territory(home)
                mutate(home)
                result = self.run_check(home)
                self.assertEqual(result.returncode, 1)
                self.assertIn("FAIL " + expected, result.stdout)
                self.assertIn("surface-check: FAILED", result.stdout)


class CliTests(unittest.TestCase):
    def test_main_renders_every_artifact_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan_value()))
            out = root / "binding"
            self.assertEqual(main(["--plan", str(plan_path), "--out", str(out)]), 0)
            rendered = binding_artifacts(plan_from_mapping(plan_value()))
            rendered["manifest"] = render_binding_manifest(
                plan_from_mapping(plan_value())
            )
            for name, data in rendered.items():
                target = out / ARTIFACT_FILENAMES[name]
                self.assertEqual(target.read_bytes(), data, name)
                mode = stat.S_IMODE(target.stat().st_mode)
                self.assertEqual(mode, 0o600, name)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode) & 0o777, 0o700)

    def test_main_refuses_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            broken = root / "broken.json"
            broken.write_text("{not json")
            self.assertEqual(
                main(["--plan", str(broken), "--out", str(root / "out")]), 2
            )
            missing = root / "missing.json"
            self.assertEqual(
                main(["--plan", str(missing), "--out", str(root / "out")]), 2
            )
            invalid = root / "invalid.json"
            invalid.write_text(json.dumps(plan_value(being_name="Nope")))
            self.assertEqual(
                main(["--plan", str(invalid), "--out", str(root / "out")]), 2
            )


if __name__ == "__main__":
    unittest.main()
