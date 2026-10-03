"""The neutral territory binding is derived, deterministic and fail-closed."""

from __future__ import annotations

import hashlib
import json
import os
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
    OWNER_CLIENT_SCHEMA,
    NeutralBindingError,
    binding_artifacts,
    chat_skill_artifacts,
    compose_codex_config,
    main,
    owner_client_plan_from_mapping,
    plan_from_mapping,
    render_binding_manifest,
    render_codex_skills_fragment,
    render_env_fragment,
    render_hermes_skills_fragment,
    render_hmk_wrapper,
    render_owner_client,
    render_service_env,
    render_surface_check,
    skill_discovery_from_mapping,
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


class HostSpecificBindingTests(unittest.TestCase):
    def test_custom_hermes_home_checks_the_actual_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            build_territory(home)
            actual_home = home / "agents/compaii/hermes-home"
            actual_home.mkdir(parents=True)
            (home / ".hermes/config.yaml").rename(actual_home / "config.yaml")
            value = plan_value(
                home=str(home),
                env_file=str(home / ".hermes/.env"),
                wrapper_path=str(home / ".local/bin/hmk"),
            )
            script = home / "surface_check.py"
            script.write_bytes(render_surface_check(plan_from_mapping(value)))
            before = subprocess.run(
                [sys.executable, str(script)], capture_output=True, check=False
            )
            self.assertEqual(before.returncode, 1)
            self.assertIn(b"FAIL hermes-config-present", before.stdout)
            value["hermes_home"] = str(actual_home)
            plan = plan_from_mapping(value)
            script.write_bytes(render_surface_check(plan))
            after = subprocess.run(
                [sys.executable, str(script)], capture_output=True, check=False
            )
            self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
            self.assertIn(b"surface-check: ok", after.stdout)
            manifest = json.loads(render_binding_manifest(plan))
            self.assertEqual(manifest["paths"]["hermes_home"], str(actual_home))
            self.assertEqual(
                manifest["paths"]["memory_base"],
                str(home / ".agents/memory/compaii/agent-memory"),
            )

    def test_optional_command_fields_are_closed_and_canonical(self) -> None:
        command = {
            "python": "/usr/bin/python3",
            "scripts_root": HOME + "/vendor/hmk/scripts",
            "workspace_root": HOME + "/agents/compaii",
        }
        self.assertIsNotNone(plan_from_mapping(plan_value(hmk=command)).hmk)
        assert_code(self, plan_value(hmk=None), "invalid_hmk_command")
        assert_code(
            self, plan_value(hmk={**command, "extra": True}), "invalid_hmk_command"
        )
        assert_code(self, plan_value(hermes_home=None), "invalid_hermes_home")
        assert_code(
            self, plan_value(hermes_home=HOME + "/../other"), "invalid_hermes_home"
        )
        assert_code(
            self,
            plan_value(harnesses=["codex"], hermes_home=HOME + "/hermes"),
            "hermes_not_in_binding",
        )
        for name, code in (
            ("python", "invalid_hmk_python"),
            ("scripts_root", "invalid_hmk_scripts_root"),
            ("workspace_root", "invalid_hmk_workspace_root"),
        ):
            assert_code(
                self, plan_value(hmk={**command, name: HOME + "/../other"}), code
            )
        assert_code(
            self,
            plan_value(hmk={**command, "scripts_root": "/etc/scripts"}),
            "invalid_hmk_scripts_root",
        )

    def test_rendered_wrapper_invokes_native_script_with_neutral_pool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            scripts = home / "vendor/hmk/scripts"
            scripts.mkdir(parents=True)
            workspace = home / "agents/compaii"
            workspace.mkdir(parents=True)
            env_file = home / "memory.env"
            marker = home / "must-not-execute"
            env_file.write_text(f"UNTRUSTED=$(touch {marker})\n")
            target = scripts / "memoryctl.py"
            target.write_text(
                "import os,json,sys\n"
                "print(json.dumps({'argv':sys.argv[1:],'cwd':os.getcwd(),"
                "'base':os.environ['HMK_AGENT_MEMORY_BASE'],"
                "'hermes_base':os.environ['HERMES_AGENT_MEMORY_BASE'],"
                "'env_file':os.environ['HMK_ENV_FILE'],"
                "'workspace':os.environ['HMK_WORKSPACE_ROOT'],"
                "'db_override':os.environ.get('HMK_DB_PATH'),"
                "'provider':os.environ.get('HMK_EMBED_PROVIDER')}))\n"
            )
            value = plan_value(
                home=str(home),
                env_file=str(env_file),
                wrapper_path=str(home / "hmk"),
                hmk={
                    "python": sys.executable,
                    "scripts_root": str(scripts),
                    "workspace_root": str(workspace),
                },
            )
            plan = plan_from_mapping(value)
            wrapper = home / "hmk"
            wrapper.write_bytes(render_hmk_wrapper(plan))
            wrapper.chmod(0o700)
            environment = {
                **os.environ,
                "HMK_DB_PATH": str(home / "wrong.db"),
                "HMK_EMBED_PROVIDER": "existing-provider",
                "HMK_AGENT_MEMORY_BASE": str(home / "wrong-pool"),
            }
            result = subprocess.run(
                [str(wrapper), "memoryctl.py", "stats", "literal argument"],
                env=environment,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            native = json.loads(result.stdout)
            self.assertEqual(native["argv"], ["stats", "literal argument"])
            self.assertEqual(native["cwd"], str(workspace))
            self.assertEqual(native["workspace"], str(workspace))
            self.assertEqual(native["base"], plan.memory_base)
            self.assertEqual(native["hermes_base"], plan.memory_base)
            self.assertEqual(native["env_file"], str(env_file))
            self.assertIsNone(native["db_override"])
            self.assertEqual(native["provider"], "existing-provider")
            self.assertFalse(marker.exists())
            manifest = json.loads(render_binding_manifest(plan))
            self.assertEqual(
                manifest["artifacts"]["hmk_wrapper"],
                hashlib.sha256(wrapper.read_bytes()).hexdigest(),
            )
            self.assertEqual(manifest["hmk_command"], value["hmk"])
            for argument in ("../memoryctl.py", str(target), "--help", "missing.py"):
                refused = subprocess.run(
                    [str(wrapper), argument], capture_output=True, check=False
                )
                self.assertEqual(refused.returncode, 2, argument)
            target.unlink()
            (scripts / "elsewhere.py").write_text("print('must not execute')\n")
            target.symlink_to(scripts / "elsewhere.py")
            refused = subprocess.run(
                [str(wrapper), "memoryctl.py"], capture_output=True, check=False
            )
            self.assertEqual(refused.returncode, 2)
            out = home / "rendered-binding"
            plan_file = home / "binding-plan.json"
            plan_file.write_text(json.dumps(value))
            self.assertEqual(main(["--plan", str(plan_file), "--out", str(out)]), 0)
            self.assertEqual((out / "hmk").read_bytes(), wrapper.read_bytes())
            self.assertEqual(stat.S_IMODE((out / "hmk").stat().st_mode), 0o700)


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


def client_plan_value(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": OWNER_CLIENT_SCHEMA,
        "venv_python": HOME + "/.local/share/daimon-matrix/body-a/venv/bin/python",
        "state_relative": ".local/state/daimon-matrix/body-a",
        "client_label": "TestA's Codex embodiment on testhost",
        "prog": "testa-codex",
    }
    value.update(overrides)
    return value


class OwnerClientTests(unittest.TestCase):
    def test_render_is_deterministic_and_valid_python(self) -> None:
        plan = owner_client_plan_from_mapping(client_plan_value())
        first = render_owner_client(plan)
        self.assertEqual(first, render_owner_client(plan))
        compile(first.decode("utf-8"), "owner-client", "exec")
        text = first.decode("utf-8")
        self.assertTrue(text.startswith("#!" + HOME))
        self.assertIn('prog="testa-codex"', text)
        self.assertIn(
            'STATE = pathlib.Path.home() / ".local/state/daimon-matrix/body-a"',
            text,
        )
        self.assertIn("TestA's Codex embodiment on testhost", text)

    def test_plan_fails_closed(self) -> None:
        def code(value: Any) -> str:
            with self.assertRaises(NeutralBindingError) as caught:
                owner_client_plan_from_mapping(value)
            return str(caught.exception)

        self.assertEqual(code(["nope"]), "invalid_client_plan")
        self.assertEqual(code(client_plan_value(extra="x")), "invalid_client_plan")
        self.assertEqual(
            code(client_plan_value(schema="dm.owner-client/v0")),
            "unsupported_client_schema",
        )
        self.assertEqual(
            code(client_plan_value(venv_python="relative/python")),
            "invalid_venv_python",
        )
        self.assertEqual(
            code(client_plan_value(state_relative="/absolute/path")),
            "invalid_state_relative",
        )
        self.assertEqual(
            code(client_plan_value(client_label='bad "label"')),
            "invalid_client_label",
        )
        self.assertEqual(code(client_plan_value(prog="Bad Prog")), "invalid_prog")

    def test_cli_renders_client_and_pins_its_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan_value()))
            client_path = root / "client-plan.json"
            client_path.write_text(json.dumps(client_plan_value()))
            out = root / "binding"
            self.assertEqual(
                main(
                    [
                        "--plan",
                        str(plan_path),
                        "--client-plan",
                        str(client_path),
                        "--out",
                        str(out),
                    ]
                ),
                0,
            )
            client = out / "testa-codex"
            expected = render_owner_client(
                owner_client_plan_from_mapping(client_plan_value())
            )
            self.assertEqual(client.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(client.stat().st_mode), 0o700)
            manifest = json.loads((out / ARTIFACT_FILENAMES["manifest"]).read_bytes())
            self.assertEqual(
                manifest["artifacts"]["owner_client"],
                hashlib.sha256(expected).hexdigest(),
            )

    def test_cli_refuses_bad_client_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan_value()))
            broken = root / "client.json"
            broken.write_text("{not json")
            self.assertEqual(
                main(
                    [
                        "--plan",
                        str(plan_path),
                        "--client-plan",
                        str(broken),
                        "--out",
                        str(root / "out"),
                    ]
                ),
                2,
            )
            invalid = root / "invalid-client.json"
            invalid.write_text(json.dumps(client_plan_value(prog="NO")))
            self.assertEqual(
                main(
                    [
                        "--plan",
                        str(plan_path),
                        "--client-plan",
                        str(invalid),
                        "--out",
                        str(root / "out"),
                    ]
                ),
                2,
            )

    def test_rendered_client_works_hosted_and_never_bypasses_the_service(
        self,
    ) -> None:
        """The client reaches the body through its daemon, or in process, and reads
        through the service.

        A body may be hosted by daimon-matrixd — which owns the state-root lock, so
        an in-process load cannot coexist with it — or used on demand with no daemon
        at all. One rendered artifact has to serve both, and the socket must be
        preferred when present, falling back only when nothing is listening.

        Reading the ledger directly is forbidden here on purpose: it bypasses the
        capability and audience checks the service enforces, and it cannot work at
        all while a daemon holds the lock.
        """
        rendered = render_owner_client(
            owner_client_plan_from_mapping(client_plan_value())
        ).decode("utf-8")
        self.assertNotIn("@@", rendered)
        compile(rendered.split("\n", 1)[1], "<owner-client>", "exec")
        # socket first, with an explicit and narrow fallback condition
        self.assertIn("LocalClient(socket_path, config).send(request)", rendered)
        self.assertIn('str(error) != "daemon_unavailable"', rendered)
        self.assertIn("runtime = _runtime()", rendered)
        # conversation reads go through the service, never around it
        self.assertIn('"we.conversation.page"', rendered)
        self.assertNotIn("service.ledger", rendered)
        # the in-process path stays confined to _send: hand the request to the
        # service, then verify the reply against that runtime's own identity
        for expected in (
            "response = runtime.service.handle(request)",
            "expected_server=runtime.service.origin",
            '"runtime_id": runtime.service.runtime_id',
            '"runtime_label": runtime.service.runtime_label',
        ):
            self.assertIn(expected, rendered)
        self.assertEqual(rendered.count("runtime.service."), 4)
        # a stored capability that does not carry a method is reported in one line,
        # not raised as a traceback: creating the request already authenticates it
        # against the capability, so the refusal can arrive before anything is sent
        self.assertIn("except (ClientError, LocalApiError) as error:", rendered)
        self.assertIn("no está al alcance de la capability de este cuerpo", rendered)


class SkillDiscoveryTests(unittest.TestCase):
    def discovery(self) -> dict[str, Any]:
        return {
            "schema": "dm.skill-discovery/v1",
            "packages": [
                {
                    "path": "memory",
                    "sha256": "a" * 64,
                    "auxiliary_skills": [
                        "references/example/SKILL.md",
                        "librarian/SKILL.md",
                    ],
                },
                {
                    "path": "memory/librarian",
                    "sha256": "b" * 64,
                    "auxiliary_skills": [],
                },
            ],
        }

    def test_nested_root_survives_parent_auxiliary_classification(self) -> None:
        import tomllib

        plan = plan_from_mapping(plan_value())
        config = tomllib.loads(
            render_codex_skills_fragment(plan, self.discovery()).decode()
        )
        self.assertEqual(
            config["skills"]["config"],
            [
                {
                    "path": SKILLS_ROOT + "/memory/references/example/SKILL.md",
                    "enabled": False,
                }
            ],
        )
        manifest = json.loads(
            render_binding_manifest(plan, skill_discovery=self.discovery())
        )
        self.assertEqual(
            manifest["artifacts"]["codex_skills_fragment"],
            hashlib.sha256(
                render_codex_skills_fragment(plan, self.discovery())
            ).hexdigest(),
        )
        changed = self.discovery()
        changed["packages"][0]["sha256"] = "c" * 64
        self.assertNotEqual(
            render_binding_manifest(plan, skill_discovery=changed),
            render_binding_manifest(plan, skill_discovery=self.discovery()),
        )

    def test_reordering_is_deterministic_and_paths_are_deduplicated(self) -> None:
        plan = plan_from_mapping(plan_value())
        value = self.discovery()
        value["packages"].reverse()
        self.assertEqual(
            render_binding_manifest(plan, skill_discovery=value),
            render_binding_manifest(plan, skill_discovery=self.discovery()),
        )

    def test_untrusted_locator_cannot_escape_or_inject_configuration(self) -> None:
        for bad in [
            "../outside",
            "memory/../outside",
            "/absolute",
            'pkg"\\n',
            "pkg/./child",
        ]:
            value = self.discovery()
            value["packages"][0]["path"] = bad
            with self.subTest(path=bad), self.assertRaises(NeutralBindingError):
                skill_discovery_from_mapping(value)
        for bad in [
            "../SKILL.md",
            "/tmp/SKILL.md",
            "SKILL.md",
            "references/../../SKILL.md",
        ]:
            value = self.discovery()
            value["packages"][0]["auxiliary_skills"] = [bad]
            with self.subTest(auxiliary=bad), self.assertRaises(NeutralBindingError):
                skill_discovery_from_mapping(value)
        value = self.discovery()
        value["packages"][0]["sha256"] = "invalid"
        with self.assertRaises(NeutralBindingError):
            skill_discovery_from_mapping(value)
        value = self.discovery()
        value["packages"].append(value["packages"][0])
        with self.assertRaises(NeutralBindingError):
            skill_discovery_from_mapping(value)

    def test_cli_binds_discovery_and_refuses_before_writing_invalid_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_file = root / "binding.json"
            plan_file.write_text(json.dumps(plan_value()))
            skill_file = root / "skills.json"
            skill_file.write_text(json.dumps(self.discovery()))
            out = root / "out"
            args = [
                "--plan",
                str(plan_file),
                "--skill-plan",
                str(skill_file),
                "--out",
                str(out),
            ]
            self.assertEqual(main(args), 0)
            fragment = out / "codex_skills_fragment.toml"
            self.assertEqual(stat.S_IMODE(fragment.stat().st_mode), 0o600)
            before = {f.name: f.read_bytes() for f in out.iterdir()}
            skill_file.write_text('{"schema":"dm.skill-discovery/v1","packages":[]}')
            self.assertEqual(main(args), 2)
            self.assertEqual(before, {f.name: f.read_bytes() for f in out.iterdir()})

    def test_composition_preserves_baseline_policy_and_refuses_reapplication(
        self,
    ) -> None:
        import tomllib

        plan = plan_from_mapping(plan_value())
        baseline = b'model = "fixture"\n[features]\nhooks = false\nmemories = false\n'
        composed = compose_codex_config(plan, self.discovery(), baseline)
        self.assertTrue(composed.startswith(baseline))
        parsed = tomllib.loads(composed.decode())
        self.assertEqual(parsed["features"], {"hooks": False, "memories": False})
        with self.assertRaisesRegex(NeutralBindingError, "codex_skill_policy_conflict"):
            compose_codex_config(plan, self.discovery(), composed)
        with self.assertRaisesRegex(NeutralBindingError, "invalid_codex_baseline"):
            compose_codex_config(plan, self.discovery(), b"[broken")
        manifest = json.loads(
            render_binding_manifest(
                plan,
                skill_discovery=self.discovery(),
                codex_baseline=baseline,
            )
        )
        self.assertEqual(
            manifest["codex_baseline_sha256"], hashlib.sha256(baseline).hexdigest()
        )
        self.assertEqual(
            manifest["artifacts"]["codex_config"], hashlib.sha256(composed).hexdigest()
        )

    def test_cli_emits_packaged_chat_and_composed_profile_without_changing_inputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_file = root / "binding.json"
            plan_file.write_text(json.dumps(plan_value()))
            skill_file = root / "skills.json"
            skill_file.write_text(json.dumps(self.discovery()))
            baseline_file = root / "baseline.toml"
            baseline_file.write_bytes(b'model = "fixture"\n')
            out = root / "out"
            args = [
                "--plan",
                str(plan_file),
                "--skill-plan",
                str(skill_file),
                "--codex-config",
                str(baseline_file),
                "--chat-skill",
                "--out",
                str(out),
            ]
            before = baseline_file.read_bytes()
            self.assertEqual(main(args), 0)
            self.assertEqual(baseline_file.read_bytes(), before)
            self.assertEqual(
                (out / "codex_config.toml").read_bytes(),
                compose_codex_config(
                    plan_from_mapping(plan_value()), self.discovery(), before
                ),
            )
            artifacts = chat_skill_artifacts()
            self.assertEqual(
                set(artifacts),
                {"chat_skill_body", "chat_skill_openai", "chat_skill_hermes"},
            )
            for name, raw in artifacts.items():
                emitted = out / ARTIFACT_FILENAMES[name]
                self.assertEqual(emitted.read_bytes(), raw)
                self.assertEqual(stat.S_IMODE(emitted.stat().st_mode), 0o600)
            manifest = json.loads((out / "binding-manifest.json").read_bytes())
            for name, raw in artifacts.items():
                self.assertEqual(
                    manifest["artifacts"][name], hashlib.sha256(raw).hexdigest()
                )
            for adapter in ["chat_skill_openai", "chat_skill_hermes"]:
                self.assertEqual(
                    artifacts[adapter], b"policy:\n  allow_implicit_invocation: false\n"
                )
            baseline_file.write_bytes((out / "codex_config.toml").read_bytes())
            output_before = {
                f.relative_to(out): f.read_bytes()
                for f in out.rglob("*")
                if f.is_file()
            }
            self.assertEqual(main(args), 2)
            self.assertEqual(
                output_before,
                {
                    f.relative_to(out): f.read_bytes()
                    for f in out.rglob("*")
                    if f.is_file()
                },
            )


if __name__ == "__main__":
    unittest.main()
