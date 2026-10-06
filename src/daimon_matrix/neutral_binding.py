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
import tomllib
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
    "codex_skills_fragment": "codex_skills_fragment.toml",
    "codex_config": "codex_config.toml",
    "chat_skill_body": "skills/daimon-chat/SKILL.md",
    "chat_skill_openai": "skills/daimon-chat/agents/openai.yaml",
    "chat_skill_hermes": "skills/daimon-chat/agents/hermes.yaml",
    "hmk_wrapper": "hmk",
}

SKILL_DISCOVERY_SCHEMA: Final = "dm.skill-discovery/v1"
_SKILL_PATH: Final = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9._-]+)*$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")

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
_OPTIONAL_FIELDS: Final = frozenset({"hermes_home", "hmk"})


class NeutralBindingError(ValueError):
    """Stable fail-closed error. A binding is derived or refused, never guessed."""


@dataclass(frozen=True)
class HMKCommandPlan:
    """Explicit existing native tooling, independent of either harness."""

    python: str
    scripts_root: str
    workspace_root: str


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
    hermes_home: str | None = None
    hmk: HMKCommandPlan | None = None

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


def _command_path(value: Any, code: str, home: str | None = None) -> str:
    result = (
        _text(value, code, _ABS_PATH)
        if home is None
        else _under_home(value, home, code)
    )
    if any(part in {".", ".."} for part in result.split("/")):
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
    if set(value) - _OPTIONAL_FIELDS != fields:
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
    hermes_home = None
    if "hermes_home" in value:
        if "hermes" not in harnesses_raw:
            raise NeutralBindingError("hermes_not_in_binding")
        hermes_home = _command_path(value["hermes_home"], "invalid_hermes_home", home)
    hmk = None
    if "hmk" in value:
        command = value["hmk"]
        if not isinstance(command, Mapping) or set(command) != {
            "python",
            "scripts_root",
            "workspace_root",
        }:
            raise NeutralBindingError("invalid_hmk_command")
        hmk = HMKCommandPlan(
            python=_command_path(command["python"], "invalid_hmk_python"),
            scripts_root=_command_path(
                command["scripts_root"], "invalid_hmk_scripts_root", home
            ),
            workspace_root=_command_path(
                command["workspace_root"], "invalid_hmk_workspace_root", home
            ),
        )
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
        hermes_home=hermes_home,
        hmk=hmk,
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


def render_hmk_wrapper(plan: NeutralBindingPlan) -> bytes:
    """Explicit native script invocation; never source an env file as shell code."""
    if plan.hmk is None:
        raise NeutralBindingError("hmk_command_not_in_binding")
    # Paths use the closed absolute-path alphabet, so single-quoted literals
    # cannot introduce expansions. Native HMK reads its configured env file for
    # provider settings; shared-pool selection is explicit before module import.
    script = f"""#!/bin/sh
# Rendered dm.neutral-binding/v1; one explicit human-requested HMK invocation.
set -eu
if [ "$#" -lt 1 ]; then
    echo 'hmk: script name required' >&2
    exit 2
fi
case "$1" in
    *[!A-Za-z0-9_.-]*|.*|*..*|'') echo 'hmk: invalid script name' >&2; exit 2 ;;
    *.py) ;;
    *) echo 'hmk: Python script name required' >&2; exit 2 ;;
esac
target='{plan.hmk.scripts_root}/'"$1"
shift
if [ ! -f "$target" ] || [ -L "$target" ]; then
    echo 'hmk: native script unavailable' >&2
    exit 2
fi
export HMK_DB_PATH='{plan.memory_base}/library.db'
export HMK_AGENT_MEMORY_BASE='{plan.memory_base}'
export HERMES_AGENT_MEMORY_BASE='{plan.memory_base}'
export HMK_ENV_FILE='{plan.env_file}'
export HMK_WORKSPACE_ROOT='{plan.hmk.workspace_root}'
cd '{plan.hmk.workspace_root}'
exec '{plan.hmk.python}' "$target" "$@"
"""
    return script.encode()


def skill_discovery_from_mapping(value: Any) -> dict[str, Any]:
    """Validate owner-selected package locators, digests and auxiliary documents.

    Digests describe supplied packages; they are not trust or adoption decisions.
    No directory scan, source import, installation or tool execution occurs.
    """
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema", "packages"}
        or value["schema"] != SKILL_DISCOVERY_SCHEMA
        or not isinstance(value["packages"], list)
        or not value["packages"]
    ):
        raise NeutralBindingError("invalid_skill_discovery")
    packages: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value["packages"]:
        if not isinstance(item, Mapping) or set(item) != {
            "path",
            "sha256",
            "auxiliary_skills",
        }:
            raise NeutralBindingError("invalid_skill_package")
        path = _text(item["path"], "invalid_skill_path", _SKILL_PATH)
        if any(part in {".", ".."} for part in path.split("/")) or path in seen:
            raise NeutralBindingError("invalid_skill_path")
        seen.add(path)
        digest = _text(item["sha256"], "invalid_skill_digest", _SHA256)
        auxiliary = item["auxiliary_skills"]
        if not isinstance(auxiliary, list):
            raise NeutralBindingError("invalid_auxiliary_skills")
        documents: set[str] = set()
        for raw in auxiliary:
            relative = _text(raw, "invalid_auxiliary_skill_path", _SKILL_PATH)
            if (
                not relative.endswith("/SKILL.md")
                or any(part in {".", ".."} for part in relative.split("/"))
                or relative in documents
            ):
                raise NeutralBindingError("invalid_auxiliary_skill_path")
            documents.add(relative)
        packages.append(
            dict(path=path, sha256=digest, auxiliary_skills=sorted(documents))
        )
    return dict(
        schema=SKILL_DISCOVERY_SCHEMA,
        packages=sorted(packages, key=lambda p: p["path"]),
    )


def render_codex_skills_fragment(plan: NeutralBindingPlan, value: Any) -> bytes:
    """Disable auxiliary SKILL.md files without disabling declared nested roots."""
    if "codex" not in plan.harnesses:
        raise NeutralBindingError("codex_not_in_binding")
    return render_codex_skills_fragment_at_root(plan.skills_root, value)


def render_codex_skills_fragment_at_root(skills_root: str, value: Any) -> bytes:
    """Render the same discovery controls for a verified local package projection."""
    _text(skills_root, "invalid_skills_root", _ABS_PATH)
    discovery = skill_discovery_from_mapping(value)
    roots = {package["path"] + "/SKILL.md" for package in discovery["packages"]}
    auxiliary = {
        package["path"] + "/" + relative
        for package in discovery["packages"]
        for relative in package["auxiliary_skills"]
    } - roots
    lines = ["# Owner-selected auxiliary documents; no package adoption or authority."]
    for relative in sorted(auxiliary):
        lines.extend(
            [
                "",
                "[[skills.config]]",
                "path = " + json.dumps(skills_root + "/" + relative),
                "enabled = false",
            ]
        )
    return ("\n".join(lines) + "\n").encode()


def compose_codex_config(
    plan: NeutralBindingPlan, value: Any, baseline: bytes
) -> bytes:
    """Compose a prepared rendered baseline once; refuse conflicting skill policy."""
    try:
        config = tomllib.loads(baseline.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise NeutralBindingError("invalid_codex_baseline") from error
    skills = config.get("skills", {})
    if not isinstance(skills, Mapping) or "config" in skills:
        raise NeutralBindingError("codex_skill_policy_conflict")
    result = baseline + b"\n" + render_codex_skills_fragment(plan, value)
    try:
        tomllib.loads(result.decode("utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise NeutralBindingError("invalid_composed_codex_config") from error
    return result


def chat_skill_artifacts() -> dict[str, bytes]:
    """Packaged neutral body/adapters only: no connection, hooks or credentials."""
    base = Path(__file__).parent / "neutral_skill_assets" / "daimon-chat"
    return {
        "chat_skill_body": (base / "SKILL.md").read_bytes(),
        "chat_skill_openai": (base / "agents" / "openai.yaml").read_bytes(),
        "chat_skill_hermes": (base / "agents" / "hermes.yaml").read_bytes(),
    }


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
    if plan.hermes_home is not None:
        script = script.replace(
            'config = Path(HOME) / ".hermes" / "config.yaml"',
            f'config = Path({plan.hermes_home!r}) / "config.yaml"',
        )
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
    if plan.hmk is not None:
        artifacts["hmk_wrapper"] = render_hmk_wrapper(plan)
    return artifacts


def render_binding_manifest(
    plan: NeutralBindingPlan,
    owner_client_digest: str | None = None,
    skill_discovery: Any = None,
    codex_baseline: bytes | None = None,
    include_chat_skill: bool = False,
) -> bytes:
    """Content-addressed manifest binding plan, paths and artifact digests."""
    artifacts = {
        name: _sha256(data) for name, data in sorted(binding_artifacts(plan).items())
    }
    if owner_client_digest is not None:
        artifacts["owner_client"] = owner_client_digest
    if skill_discovery is not None:
        artifacts["codex_skills_fragment"] = _sha256(
            render_codex_skills_fragment(plan, skill_discovery)
        )
    if codex_baseline is not None:
        if skill_discovery is None:
            raise NeutralBindingError("skill_plan_required_for_codex_config")
        artifacts["codex_config"] = _sha256(
            compose_codex_config(plan, skill_discovery, codex_baseline)
        )
    if include_chat_skill:
        artifacts.update(
            {name: _sha256(data) for name, data in chat_skill_artifacts().items()}
        )
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
    if plan.hermes_home is not None:
        paths["hermes_home"] = plan.hermes_home
    body: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "being_name": plan.being_name,
        "host_word": plan.host_word,
        "platform": plan.platform,
        "harnesses": list(plan.harnesses),
        "paths": paths,
        "artifacts": artifacts,
    }
    if skill_discovery is not None:
        body["skill_discovery"] = skill_discovery_from_mapping(skill_discovery)
    if plan.hmk is not None:
        body["hmk_command"] = {
            "python": plan.hmk.python,
            "scripts_root": plan.hmk.scripts_root,
            "workspace_root": plan.hmk.workspace_root,
        }
    if codex_baseline is not None:
        body["codex_baseline_sha256"] = _sha256(codex_baseline)
    try:
        return canonical_bytes(body)
    except CanonicalError as exception:
        raise NeutralBindingError("manifest_not_canonical") from exception


OWNER_CLIENT_SCHEMA: Final = "dm.owner-client/v1"

_STATE_RELATIVE: Final = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_CLIENT_LABEL: Final = re.compile(r"^[A-Za-z0-9 '.@-]{1,120}$")
_PROG: Final = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
_CLIENT_FIELDS: Final = frozenset(
    {"schema", "venv_python", "state_relative", "client_label", "prog"}
)


@dataclass(frozen=True)
class OwnerClientPlan:
    """Closed plan for one body's owner-local client. No secrets, no paths
    outside the owner home convention; the client is a rendered artifact."""

    venv_python: str
    state_relative: str
    client_label: str
    prog: str


def owner_client_plan_from_mapping(value: Any) -> OwnerClientPlan:
    if not isinstance(value, Mapping):
        raise NeutralBindingError("invalid_client_plan")
    if set(value) != _CLIENT_FIELDS:
        raise NeutralBindingError("invalid_client_plan")
    if value["schema"] != OWNER_CLIENT_SCHEMA:
        raise NeutralBindingError("unsupported_client_schema")
    return OwnerClientPlan(
        venv_python=_text(value["venv_python"], "invalid_venv_python", _ABS_PATH),
        state_relative=_text(
            value["state_relative"], "invalid_state_relative", _STATE_RELATIVE
        ),
        client_label=_text(
            value["client_label"], "invalid_client_label", _CLIENT_LABEL
        ),
        prog=_text(value["prog"], "invalid_prog", _PROG),
    )


_OWNER_CLIENT_TEMPLATE: Final = r'''#!@@VENV_PYTHON@@
"""Owner-local client for @@CLIENT_LABEL@@.

One invocation does one thing a human asked for, then exits. This script starts
no daemon, no poller, no timer and no autonomous reply: authority and custody
stay inside the runtime, and the script holds a single least-authority client
capability. Reading a message never authorizes answering it.

If the owner hosts this body with daimon-matrixd, the script talks to that
daemon over its socket; otherwise it loads the runtime in process. It never
does both, because the daemon owns the state-root lock.

    compaii-codex status
    compaii-codex we                       # this being's embodiments
    compaii-codex say --text "..." [--to EMBODIMENT_ID]... [--thread UUID]
    compaii-codex read [--thread UUID] [--limit N]
    compaii-codex say --retry UUID        # recover the exact saved request
    compaii-codex methods                 # installed, disjoint capabilities
    compaii-codex call METHOD             # JSON parameters on stdin
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import stat
import sys
import uuid

from daimon_matrix.client import (
    ClientConfig,
    ClientError,
    LocalClient,
    load_json_document,
    load_prepared_request,
    read_capability_key,
    store_prepared_request,
)
from daimon_matrix.daemon import DaemonError, acquire_lock
from daimon_matrix.local_api import (
    LocalApiError,
    create_request,
    request_hash,
    verify_response,
)
from daimon_matrix.native_egress import closed_visibility
from daimon_matrix.runtime import load_runtime
from daimon_matrix.service import OPERATOR_CAPABILITY_PROFILES

STATE = pathlib.Path.home() / @@STATE_RELATIVE@@
RUNTIME = STATE / "runtime"


def _clock() -> int:
    import time

    return time.time_ns() // 1_000_000


def _runtime():
    password = (STATE / "body.password").read_bytes().strip()
    return load_runtime(
        RUNTIME,
        "runtime.json",
        lambda: bytearray(password),
        clock=_clock,
        egress=closed_visibility(clock=_clock, catalog_mode="migrate"),
    )


def _load_config(directory, key_name):
    # read_capability_key owns and closes the descriptor it is given.
    descriptor = os.open(directory / key_name, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or (
        stat.S_IMODE(info.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise ClientError("capability_key_not_owner_only")
    key = read_capability_key(descriptor)
    return ClientConfig.load(directory / "client.json", key)


def _profile(primary, role):
    config = _load_config(RUNTIME / "operator-clients" / role, "capability.key")
    if (
        config.expected_server != primary.expected_server
        or config.runtime_id != primary.runtime_id
        or config.runtime_label != primary.runtime_label
    ):
        raise ClientError("operator_profile_body_mismatch")
    if frozenset(config.capability.methods) != OPERATOR_CAPABILITY_PROFILES[role]:
        raise ClientError("operator_profile_methods_mismatch")
    return config


def _config(method):
    primary = _load_config(RUNTIME, "client.key")
    if method in primary.capability.methods:
        return primary
    for role, methods in OPERATOR_CAPABILITY_PROFILES.items():
        if method in methods and role != "observe":
            return _profile(primary, role)
    raise ClientError("method_not_issued")


def _methods():
    primary = _load_config(RUNTIME, "client.key")
    configs = {"primary": primary}
    for role in sorted(OPERATOR_CAPABILITY_PROFILES):
        directory = RUNTIME / "operator-clients" / role
        if role != "observe" and directory.exists():
            configs[role] = _profile(primary, role)
    return {
        role: {"active": config.capability.active_at(_clock()),
               "methods": list(config.capability.methods)}
        for role, config in configs.items()
    }


def _send(config, request: dict) -> dict:
    """Reach the body through its daemon when one is running, else in process.

    LocalClient.send authenticates the request and verifies the exact reply, so
    the socket path needs no extra checking here. A socket file left behind by a
    stopped daemon connects to nothing and reports daemon_unavailable, which is
    the signal to load the runtime directly instead.
    """
    socket_path = RUNTIME / "matrix.sock"
    if socket_path.exists():
        try:
            return LocalClient(socket_path, config, timeout_seconds=40).send(request)
        except ClientError as error:
            if str(error) != "daemon_unavailable":
                raise
    # A timeout does not establish that the daemon stopped. Acquire its actual
    # writer lock before loading custody or touching the runtime in process.
    try:
        descriptor = acquire_lock(RUNTIME)
    except BlockingIOError:
        raise ClientError("daemon_unavailable_runtime_locked") from None
    try:
        runtime = _runtime()
        response = runtime.service.handle(request)
        return verify_response(
            response,
            config.capability,
            expected_request_id=request["request_id"],
            expected_request_hash=request_hash(request),
            expected_server=config.expected_server,
            expected_runtime={
                "runtime_id": config.runtime_id,
                "runtime_label": config.runtime_label,
            },
        )
    finally:
        os.close(descriptor)


def _call(method: str, params: dict) -> dict:
    config = _config(method)
    request = create_request(
        config.capability,
        request_id=str(uuid.uuid4()),
        issued_at_ms=_clock(),
        method=method,
        params=params,
        nonce=os.urandom(16),
    )
    return _result(_send(config, request), method)


def _result(response, method):
    if response.get("error") is not None:
        raise ClientError(f"{method}_rejected:{response['error']['code']}")
    return response["result"]


def _say(args):
    config = _config("we.converse")
    directory = STATE / "owner-requests"
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ClientError("request_store_parent_not_owner_only")
    if args.retry is not None:
        request_id = str(uuid.UUID(args.retry))
        path = directory / (request_id + ".json")
        # First parse supplies expected operation data; the SDK then checks the
        # owner-only file, authenticates every byte and checks those parameters.
        with path.open("rb") as stream:
            saved = load_json_document(stream.read(1_048_577))
        request = load_prepared_request(
            path, config.capability, method="we.converse", params=saved["params"]
        )
        if request["request_id"] != request_id or (
            request["params"].get("request_id") != request_id
        ):
            raise ClientError("request_operation_mismatch")
    else:
        request_id = (str(uuid.UUID(args.request_id)) if args.request_id
                      else str(uuid.uuid4()))
        addressees = sorted(set(args.to))
        if not addressees:
            siblings = _call("scope.we", {})["embodiments"]
            me = config.expected_server["embodiment_id"]
            addressees = sorted(row["embodiment_id"] for row in siblings
                               if row["embodiment_id"] != me
                               and row.get("manifest_status") == "active")
        if not addressees:
            raise ClientError("no_active_sibling")
        params = {"text": args.text, "addressees": addressees,
                  "request_id": request_id, "thread_id": (
                      str(uuid.UUID(args.thread)) if args.thread
                      else str(uuid.uuid4()))}
        if args.ttl_ms is not None:
            params["ttl_ms"] = args.ttl_ms
        request = create_request(
            config.capability, request_id=request_id, issued_at_ms=_clock(),
            method="we.converse", params=params, nonce=os.urandom(16),
        )
        store_prepared_request(directory / (request_id + ".json"), request)
    print(f"Saved request: {request_id}; retry with say --retry {request_id}",
          file=sys.stderr, flush=True)
    result = _result(_send(config, request), "we.converse")
    print(json.dumps({"request_id": request_id, "result": result},
                     indent=2, sort_keys=True))
    deliveries = result["deliveries"]
    delivered = deliveries and all(row["state"] == "delivered" for row in deliveries)
    return 0 if delivered else 3


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=@@PROG@@, description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="who this body is, and its integrity")
    commands.add_parser("we", help="this being's embodiments")
    commands.add_parser("methods", help="list this body's installed operation profiles")
    call = commands.add_parser("call", help="invoke an issued method with JSON stdin")
    call.add_argument("method")
    say = commands.add_parser("say", help="deliver one sealed /we message, on request")
    say.add_argument("--text")
    say.add_argument("--to", action="append", default=[])
    say.add_argument("--thread")
    say.add_argument("--request-id")
    say.add_argument("--ttl-ms", type=int)
    say.add_argument("--retry", help="retry the exact saved request UUID")
    read = commands.add_parser("read", help="read this being's conversation")
    read.add_argument("--thread")
    read.add_argument("--limit", type=int, default=40)
    args = parser.parse_args(argv)

    if args.command == "methods":
        print(json.dumps(_methods(), indent=2, sort_keys=True))
        return 0
    if args.command == "call":
        params = load_json_document(sys.stdin.buffer.read(1_048_577))
        print(json.dumps(_call(args.method, params), indent=2, sort_keys=True))
        return 0
    if args.command == "say":
        if args.retry is not None:
            if (args.text is not None or args.to or args.thread or args.request_id
                    or args.ttl_ms is not None):
                parser.error("--retry accepts no replacement parameters")
        elif args.text is None:
            parser.error("say requires --text or --retry")
        return _say(args)

    if args.command == "status":
        result = _call("runtime.status", {})
        print(
            json.dumps(
                {
                    "being_ref": result["being_ref"],
                    "manifest_hash": result["manifest_hash"][:16] + "…",
                    "local_origin": result["local_origin"],
                    "integrity": result["integrity"],
                    "counts": result["counts"],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.command == "we":
        result = _call("scope.we", {})
        rows = [
            {
                "embodiment_id": row["embodiment_id"],
                "availability": row.get("availability"),
                "manifest_status": row.get("manifest_status"),
            }
            for row in result["embodiments"]
        ]
        print(json.dumps(rows, indent=2, sort_keys=True))
        return 0

    if args.command == "read":
        params = {"after": 0, "limit": args.limit}
        if args.thread is not None:
            params["thread_id"] = args.thread
        # Through the service, not around it: the page is capability-checked and
        # arrives with the labels layer applied, so a human reads names instead
        # of opaque embodiment ids.
        page = _call("we.conversation.page", params)
        print(json.dumps(page["entries"], indent=2, sort_keys=True, default=str))
        return 0

    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (ClientError, LocalApiError, DaemonError,
            OSError, ValueError, KeyError) as error:
        # Error codes only: never dump configurations, authentication or content.
        code = error.errno if isinstance(error, OSError) else str(error)
        if type(error) in (KeyError, ValueError):
            code = "invalid_owner_request"
        print(f"owner-client: {code}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_owner_client(plan: OwnerClientPlan) -> bytes:
    """Deterministic owner-local client for one body (human-request-only)."""
    script = _OWNER_CLIENT_TEMPLATE
    for token, replacement in (
        ("@@VENV_PYTHON@@", plan.venv_python),
        ("@@CLIENT_LABEL@@", plan.client_label),
        ("@@STATE_RELATIVE@@", f'"{plan.state_relative}"'),
        ("@@PROG@@", f'"{plan.prog}"'),
    ):
        script = script.replace(token, replacement)
    return script.encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    """Render one binding: ``--plan plan.json --out DIR`` (``--client-plan``
    optional). Exit 0/2/3."""
    parser = argparse.ArgumentParser(
        description="Render the harness-neutral territory binding artifacts."
    )
    parser.add_argument("--plan", required=True, type=Path, help="binding plan JSON")
    parser.add_argument(
        "--client-plan", type=Path, default=None, help="owner-client plan JSON"
    )
    parser.add_argument("--out", required=True, type=Path, help="output directory")
    parser.add_argument(
        "--skill-plan", type=Path, help="owner-selected skill discovery plan JSON"
    )
    parser.add_argument(
        "--codex-config",
        type=Path,
        help="prepared rendered Codex baseline; requires --skill-plan",
    )
    parser.add_argument(
        "--chat-skill", action="store_true", help="emit the packaged neutral chat skill"
    )
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
    client_plan: OwnerClientPlan | None = None
    client_bytes: bytes | None = None
    if args.client_plan is not None:
        try:
            client_raw = json.loads(args.client_plan.read_bytes())
            client_plan = owner_client_plan_from_mapping(client_raw)
        except (OSError, json.JSONDecodeError):
            print("neutral-binding: client_plan_unreadable", file=sys.stderr)
            return 2
        except NeutralBindingError as error:
            print(f"neutral-binding: {error}", file=sys.stderr)
            return 2
        client_bytes = render_owner_client(client_plan)
    outputs = dict(binding_artifacts(plan))
    skill_discovery: Any = None
    if args.skill_plan is not None:
        try:
            skill_discovery = skill_discovery_from_mapping(
                json.loads(args.skill_plan.read_bytes())
            )
            outputs["codex_skills_fragment"] = render_codex_skills_fragment(
                plan, skill_discovery
            )
        except (OSError, json.JSONDecodeError):
            print("neutral-binding: skill_plan_unreadable", file=sys.stderr)
            return 2
        except NeutralBindingError as error:
            print(f"neutral-binding: {error}", file=sys.stderr)
            return 2
    if client_bytes is not None:
        outputs["owner_client"] = client_bytes
    codex_baseline: bytes | None = None
    try:
        if args.codex_config is not None:
            if skill_discovery is None:
                raise NeutralBindingError("skill_plan_required_for_codex_config")
            codex_baseline = args.codex_config.read_bytes()
            outputs["codex_config"] = compose_codex_config(
                plan, skill_discovery, codex_baseline
            )
        if args.chat_skill:
            outputs.update(chat_skill_artifacts())
    except OSError:
        print("neutral-binding: config_or_skill_unreadable", file=sys.stderr)
        return 2
    except NeutralBindingError as error:
        print(f"neutral-binding: {error}", file=sys.stderr)
        return 2
    manifest = render_binding_manifest(
        plan,
        None if client_bytes is None else _sha256(client_bytes),
        skill_discovery,
        codex_baseline,
        args.chat_skill,
    )
    outputs["manifest"] = manifest
    try:
        args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name, data in sorted(outputs.items()):
            if name == "owner_client" and client_plan is not None:
                target = args.out / client_plan.prog
                mode = 0o700
            else:
                target = args.out / ARTIFACT_FILENAMES[name]
                mode = 0o700 if name == "hmk_wrapper" else 0o600
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            os.chmod(target, mode)
    except OSError:
        print("neutral-binding: output_unwritable", file=sys.stderr)
        return 3
    print("neutral-binding: " + _sha256(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
