"""Harness-neutral territory binding for one being on one host.

The neutral territory is host-common ground owned by no harness:
``<home>/.agents/skills`` (shared skill surface, single source of truth) and
``<home>/.agents/memory/<being>/agent-memory`` (being-level memory pool; the
per-embodiment authorship lives in Matrix projection ``source_instance``, never
here). This module renders the artifacts that attach harnesses to that
territory — environment fragments, per-platform service environment, the
Hermes external-skills-root fragment, a self-contained surface check — plus a
content-addressed manifest.

Every path is derived from the closed plan ``(home, being_name)``; nothing
free-form is accepted, so the same plan renders identical bytes anywhere. A
binding is wiring and presentation: it authenticates nothing, authorizes
nothing, and never touches keys, custody, or live services. Harness
differences are preserved on purpose — the memory pool is shared, the
integration mechanism (Hermes plugin prefetch versus human-request-only
invocation elsewhere) is not normalized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes

BINDING_SCHEMA: Final = "dm.neutral-binding/v1"
MANIFEST_SCHEMA: Final = "dm.neutral-binding-manifest/v1"
PLATFORMS: Final = ("env-file", "linux-systemd", "macos-launchagent")
HARNESSES: Final = ("codex", "hermes")
MEMORY_VARS: Final = ("HMK_AGENT_MEMORY_BASE", "HERMES_AGENT_MEMORY_BASE")
ARTIFACT_FILENAMES: Final = {
    "env_fragment": "env_fragment.env",
    "service_env": "service_env.txt",
    "hermes_skills_fragment": "hermes_skills_fragment.yaml",
    "surface_check": "surface_check.py",
    "manifest": "binding-manifest.json",
}

_BEING_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
_HOST_WORD: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_ABS_PATH: Final = re.compile(r"^/[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$")
_SERVICE_UNIT: Final = re.compile(r"^[A-Za-z0-9@:._-]{1,128}\.service$")
_MAX_PATH_BYTES: Final = 200
_BASE_FIELDS: Final = frozenset(
    {
        "schema",
        "being_name",
        "host_word",
        "home",
        "platform",
        "harnesses",
        "env_file",
        "wrapper_path",
    }
)
_SYSTEMD_FIELDS: Final = _BASE_FIELDS | {"service_unit"}


class NeutralBindingError(ValueError):
    """Stable fail-closed error. A binding is derived or refused, never guessed."""


@dataclass(frozen=True)
class NeutralBindingPlan:
    """Closed owner-local plan. Territory paths are derived, never supplied."""

    being_name: str
    host_word: str
    home: str
    platform: str
    harnesses: tuple[str, ...]
    env_file: str
    wrapper_path: str
    service_unit: str | None

    @property
    def agents_root(self) -> str:
        return f"{self.home}/.agents"

    @property
    def skills_root(self) -> str:
        return f"{self.agents_root}/skills"

    @property
    def memory_root(self) -> str:
        return f"{self.agents_root}/memory"

    @property
    def memory_base(self) -> str:
        return f"{self.memory_root}/{self.being_name}/agent-memory"


def _text(value: Any, code: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_PATH_BYTES:
        raise NeutralBindingError(code)
    if pattern.fullmatch(value) is None:
        raise NeutralBindingError(code)
    return value


def _under_home(value: Any, home: str, code: str) -> str:
    result = _text(value, code, _ABS_PATH)
    if not result.startswith(home + "/"):
        raise NeutralBindingError(code)
    return result


def plan_from_mapping(value: Any) -> NeutralBindingPlan:
    """Validate a closed binding plan or refuse it with a stable code."""
    if not isinstance(value, Mapping):
        raise NeutralBindingError("invalid_binding_plan")
    platform = value.get("platform")
    if not isinstance(platform, str) or platform not in PLATFORMS:
        raise NeutralBindingError("invalid_platform")
    fields = _SYSTEMD_FIELDS if platform == "linux-systemd" else _BASE_FIELDS
    if set(value) != fields:
        raise NeutralBindingError("invalid_binding_plan")
    if value["schema"] != BINDING_SCHEMA:
        raise NeutralBindingError("unsupported_binding_schema")
    harnesses_raw = value["harnesses"]
    if (
        isinstance(harnesses_raw, (str, bytes))
        or not isinstance(harnesses_raw, Sequence)
        or not harnesses_raw
        or len(set(harnesses_raw)) != len(harnesses_raw)
        or any(item not in HARNESSES for item in harnesses_raw)
    ):
        raise NeutralBindingError("invalid_harnesses")
    home = _text(value["home"], "invalid_home", _ABS_PATH)
    service_unit: str | None = None
    if platform == "linux-systemd":
        service_unit = _text(
            value["service_unit"], "invalid_service_unit", _SERVICE_UNIT
        )
    return NeutralBindingPlan(
        being_name=_text(value["being_name"], "invalid_being_name", _BEING_NAME),
        host_word=_text(value["host_word"], "invalid_host_word", _HOST_WORD),
        home=home,
        platform=platform,
        harnesses=tuple(harnesses_raw),
        env_file=_under_home(value["env_file"], home, "invalid_env_file"),
        wrapper_path=_under_home(value["wrapper_path"], home, "invalid_wrapper_path"),
        service_unit=service_unit,
    )


def render_env_fragment(plan: NeutralBindingPlan) -> bytes:
    """Exact env-file lines that point every harness at the being's pool."""
    lines = [f"{name}={plan.memory_base}" for name in MEMORY_VARS]
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_service_env(plan: NeutralBindingPlan) -> bytes:
    """Per-platform service environment mechanism for the memory base."""
    if plan.platform == "env-file":
        return render_env_fragment(plan)
    if plan.platform == "linux-systemd":
        lines = [f'Environment="{name}={plan.memory_base}"' for name in MEMORY_VARS]
        return ("[Service]\n" + "\n".join(lines) + "\n").encode("utf-8")
    entries = "".join(
        f"\t<key>{name}</key>\n\t<string>{plan.memory_base}</string>\n"
        for name in MEMORY_VARS
    )
    return f"<key>EnvironmentVariables</key>\n<dict>\n{entries}</dict>\n".encode()


def render_hermes_skills_fragment(plan: NeutralBindingPlan) -> bytes:
    """Hermes ``skills.external_dirs`` fragment exposing the neutral surface."""
    if "hermes" not in plan.harnesses:
        raise NeutralBindingError("hermes_not_in_binding")
    return f"skills:\n  external_dirs:\n    - {plan.skills_root}\n".encode()


_CHECK_TEMPLATE: Final = r'''#!/usr/bin/env python3
"""Rendered neutral-territory surface check (dm.neutral-binding/v1).

Deterministic rendered artifact; Python 3.11+ stdlib only. Exit 0 when the
host surface matches the binding, 1 on any failure. Read-only: this script
never writes, moves, or repairs anything.
"""
import os
import sys
from pathlib import Path

HOME = @@HOME@@
SKILLS_ROOT = @@SKILLS_ROOT@@
MEMORY_BASE = @@MEMORY_BASE@@
ENV_FILE = @@ENV_FILE@@
WRAPPER_PATH = @@WRAPPER_PATH@@
PLATFORM = @@PLATFORM@@
HARNESSES = @@HARNESSES@@
MEMORY_VARS = @@MEMORY_VARS@@

FAILURES = []


def check(ok, label):
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        FAILURES.append(label)
    return ok


def frontmatter_ok(path):
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    if not text.startswith("---\n"):
        return False
    end = text.find("\n---", 3)
    if end < 0:
        return False
    has_name = has_desc = False
    for line in text[4:end].splitlines():
        if line.startswith("name:") and line[len("name:"):].strip():
            has_name = True
        if line.startswith("description:") and line[len("description:"):].strip():
            has_desc = True
    return has_name and has_desc


def check_skills():
    root = Path(SKILLS_ROOT)
    if not check(root.is_dir(), "skills-root-is-directory"):
        return
    entries = [
        entry
        for entry in sorted(root.iterdir())
        if entry.is_dir() and not entry.name.startswith(".")
    ]
    check(bool(entries), "skills-root-not-empty")
    for entry in entries:
        direct = entry / "SKILL.md"
        if direct.is_file():
            check(frontmatter_ok(direct), "skill-frontmatter:" + entry.name)
            continue
        nested = sorted(
            sub / "SKILL.md"
            for sub in entry.iterdir()
            if sub.is_dir() and (sub / "SKILL.md").is_file()
        )
        if not nested:
            check(False, "skill-directory-without-skill:" + entry.name)
            continue
        for skill_file in nested:
            check(
                frontmatter_ok(skill_file),
                "skill-frontmatter:" + skill_file.parent.name,
            )


def check_memory():
    base = Path(MEMORY_BASE)
    check(base.is_dir(), "memory-base-is-directory")
    check((base / "library.db").is_file(), "memory-library-db-present")


def check_env():
    path = Path(ENV_FILE)
    if not check(path.is_file(), "env-file-present"):
        return
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        check(False, "env-file-readable")
        return
    for var in MEMORY_VARS:
        check(var + "=" + MEMORY_BASE in lines, "env-line:" + var)


def check_wrapper():
    path = Path(WRAPPER_PATH)
    check(path.is_file(), "wrapper-present")
    check(os.access(path, os.X_OK), "wrapper-executable")


def check_discovery():
    if "hermes" in HARNESSES:
        config = Path(HOME) / ".hermes" / "config.yaml"
        if check(config.is_file(), "hermes-config-present"):
            try:
                text = config.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            home_relative = (
                "~" + SKILLS_ROOT[len(HOME):]
                if SKILLS_ROOT.startswith(HOME + "/")
                else SKILLS_ROOT
            )
            check(
                (SKILLS_ROOT in text or home_relative in text)
                and "external_dirs" in text,
                "hermes-external-skills-root-configured",
            )
    if "codex" in HARNESSES:
        check(
            SKILLS_ROOT == str(Path(HOME) / ".agents" / "skills"),
            "codex-native-skills-root",
        )


def main():
    print("surface-check platform=" + PLATFORM + " harnesses=" + ",".join(HARNESSES))
    check_skills()
    check_memory()
    check_env()
    check_wrapper()
    check_discovery()
    if FAILURES:
        print("surface-check: FAILED (" + str(len(FAILURES)) + ")")
        return 1
    print("surface-check: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def render_surface_check(plan: NeutralBindingPlan) -> bytes:
    """Self-contained read-only checker for the rendered territory."""
    script = _CHECK_TEMPLATE
    for token, replacement in (
        ("@@HOME@@", repr(plan.home)),
        ("@@SKILLS_ROOT@@", repr(plan.skills_root)),
        ("@@MEMORY_BASE@@", repr(plan.memory_base)),
        ("@@ENV_FILE@@", repr(plan.env_file)),
        ("@@WRAPPER_PATH@@", repr(plan.wrapper_path)),
        ("@@PLATFORM@@", repr(plan.platform)),
        ("@@HARNESSES@@", repr(list(plan.harnesses))),
        ("@@MEMORY_VARS@@", repr(list(MEMORY_VARS))),
    ):
        script = script.replace(token, replacement)
    return script.encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def binding_artifacts(plan: NeutralBindingPlan) -> dict[str, bytes]:
    """Every rendered artifact for the plan, keyed by manifest name."""
    artifacts = {
        "env_fragment": render_env_fragment(plan),
        "service_env": render_service_env(plan),
        "surface_check": render_surface_check(plan),
    }
    if "hermes" in plan.harnesses:
        artifacts["hermes_skills_fragment"] = render_hermes_skills_fragment(plan)
    return artifacts


def render_binding_manifest(plan: NeutralBindingPlan) -> bytes:
    """Content-addressed manifest binding plan, paths and artifact digests."""
    artifacts = {
        name: _sha256(data) for name, data in sorted(binding_artifacts(plan).items())
    }
    paths: dict[str, str] = {
        "agents_root": plan.agents_root,
        "skills_root": plan.skills_root,
        "memory_root": plan.memory_root,
        "memory_base": plan.memory_base,
        "env_file": plan.env_file,
        "wrapper_path": plan.wrapper_path,
    }
    if plan.service_unit is not None:
        paths["service_unit"] = plan.service_unit
    body: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "being_name": plan.being_name,
        "host_word": plan.host_word,
        "platform": plan.platform,
        "harnesses": list(plan.harnesses),
        "paths": paths,
        "artifacts": artifacts,
    }
    try:
        return canonical_bytes(body)
    except CanonicalError as exception:
        raise NeutralBindingError("manifest_not_canonical") from exception


def main(argv: Sequence[str] | None = None) -> int:
    """Render one binding: ``--plan plan.json --out DIR``. Exit 0/2/3."""
    parser = argparse.ArgumentParser(
        description="Render the harness-neutral territory binding artifacts."
    )
    parser.add_argument("--plan", required=True, type=Path, help="binding plan JSON")
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    args = parser.parse_args(argv)
    try:
        raw = json.loads(args.plan.read_bytes())
    except (OSError, json.JSONDecodeError):
        print("neutral-binding: plan_unreadable", file=sys.stderr)
        return 2
    try:
        plan = plan_from_mapping(raw)
    except NeutralBindingError as error:
        print(f"neutral-binding: {error}", file=sys.stderr)
        return 2
    outputs = dict(binding_artifacts(plan))
    outputs["manifest"] = render_binding_manifest(plan)
    try:
        args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, data in sorted(outputs.items()):
            target = args.out / ARTIFACT_FILENAMES[name]
            target.write_bytes(data)
            os.chmod(target, 0o600)
    except OSError:
        print("neutral-binding: output_unwritable", file=sys.stderr)
        return 3
    print("neutral-binding: " + _sha256(outputs["manifest"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
