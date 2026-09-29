#!/usr/bin/env python3
"""Read-only onboarding preflight for one host, before anything is installed.

Onboarding an existing daimon to native Matrix used to mean an operator improvising
over SSH: guessing whether the harness is the right version, whether an identity
already exists, whether a service is already holding a port, and whether the host is
one this project actually supports. Every one of those is inspectable, and asking a
human to discover them is how a duplicate being gets minted or a running body gets
disturbed.

This answers them in one command and changes nothing. It reports:

  * whether this host is one of the pilot shapes the project supports, rather than
    claiming universal platform support it has not earned;
  * the interpreter version against the interval the release is built for;
  * which harnesses are present, and their versions where a version is discoverable;
  * whether an enrollment already exists, so the operator resumes it instead of
    minting a second being -- named by principal and manifest revision, never by key
    material;
  * which supporting tools are missing;
  * with probing enabled, whether a non-loopback route exists and whether a body is
    already live on this host.

It prints no secret and no network address. Custody files are counted and named, never
opened, and interface *names* are reported instead of their addresses, because this
report is meant to be pasted into a public issue and the mesh is not public.

A verdict of ``preparation-needed`` is not a failure: it lists what has to happen
first. ``unsupported`` means this host is outside what the project has actually
validated, and says so rather than pretending otherwise.

    preflight_onboarding.py
    preflight_onboarding.py --home /Users/someone --probe
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "dm-onboarding-preflight-report/v0"

# The shapes this project has actually onboarded. Anything else is reported as
# unsupported with a reason, not silently assumed to work.
SUPPORTED_PLATFORMS = {
    ("darwin", "arm64"): "macos-launchagent",
    ("darwin", "x86_64"): "macos-launchagent",
    ("linux", "x86_64"): "linux-systemd",
    ("linux", "aarch64"): "linux-systemd",
}

# The interval the release is built and tested for.
PYTHON_MINIMUM = (3, 11)
PYTHON_MAXIMUM_EXCLUSIVE = (3, 14)

# Tools onboarding genuinely needs, and what each is needed for.
REQUIRED_TOOLS = {
    "git": "fetch the exact release and work in worktrees",
    "openssl": "generate a dedicated coordination session key",
}
RECOMMENDED_TOOLS = {
    "gh": "claim cards, open pull requests and read the tracker",
    "curl": "verify a peer route answers before trusting it",
}

# A hand-hosted body keeps its runtime at ``<state-root>/runtime``; a body
# activated by ``daimon-rebirth`` keeps it at ``<state-root>/package/runtime``.
# Matching only the first shape reports zero bodies on a host that already has
# one, which is precisely the mistake that mints a duplicate being.
STATE_ROOT_GLOBS = ("*/runtime/runtime.json", "*/*/runtime/runtime.json")
SOCKET_GLOBS = ("*/runtime/matrix.sock", "*/*/runtime/matrix.sock")
VERDICT_COMPATIBLE = "compatible"
VERDICT_PREPARATION = "preparation-needed"
VERDICT_UNSUPPORTED = "unsupported"


def _version_tuple(value: str) -> tuple[int, ...] | None:
    parts: list[int] = []
    for chunk in value.split(".")[:3]:
        digits = ""
        for character in chunk:
            if not character.isdigit():
                break
            digits += character
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or None


def _run(argv: list[str], timeout: float = 8.0) -> str | None:
    """Run one read-only command and return its whole output, or None.

    The command must exist, must not fail, and must not need input. Anything else
    is reported as absent rather than guessed at, because a preflight that invents
    an answer is worse than one that says it does not know.
    """

    executable = shutil.which(argv[0])
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, *argv[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout or completed.stderr).strip()


def inspect_platform() -> dict[str, Any]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    key = (system, machine)
    return {
        "system": system,
        "machine": machine,
        "supported": key in SUPPORTED_PLATFORMS,
        "mechanism": SUPPORTED_PLATFORMS.get(key),
        "reason": None
        if key in SUPPORTED_PLATFORMS
        else f"this project has not onboarded {system}/{machine}; the pilot shapes are "
        "macOS arm64 and x86_64, and Linux x86_64 and aarch64 with systemd user units",
    }


def inspect_python() -> dict[str, Any]:
    current = sys.version_info[:3]
    release = _run(
        [sys.executable, "-c", "import platform;print(platform.python_version())"]
    )
    actual = _version_tuple(release or "") or current
    ok = PYTHON_MINIMUM <= actual[:2] < PYTHON_MAXIMUM_EXCLUSIVE
    return {
        "version": ".".join(str(part) for part in actual),
        "executable_is_absolute": os.path.isabs(sys.executable),
        "supported": ok,
        "interval": (
            f">={PYTHON_MINIMUM[0]}.{PYTHON_MINIMUM[1]},"
            f"<{PYTHON_MAXIMUM_EXCLUSIVE[0]}.{PYTHON_MAXIMUM_EXCLUSIVE[1]}"
        ),
        "reason": None
        if ok
        else f"interpreter {'.'.join(str(p) for p in actual)} is outside the interval "
        "the release is built and tested for",
    }


def inspect_harnesses(home: Path) -> dict[str, Any]:
    """Which harnesses are present. Presence is not configuration."""

    codex_home = home / ".codex"
    codex_version_raw = _run(["codex", "--version"])
    codex_version = (
        codex_version_raw.splitlines()[0].strip() if codex_version_raw else None
    )
    hermes_home = home / ".hermes"
    hermes_version = None
    if hermes_home.is_dir():
        for candidate in ("VERSION", "version.txt"):
            path = hermes_home / candidate
            if path.is_file():
                try:
                    hermes_version = (
                        path.read_text(encoding="utf-8").strip()[:64] or None
                    )
                except OSError:
                    hermes_version = None
                break
    return {
        "codex": {
            "present": codex_version is not None or codex_home.is_dir(),
            "cli_on_path": codex_version is not None,
            "version": codex_version,
            "home_exists": codex_home.is_dir(),
            # A global AGENTS.md is what makes a Codex session on this host be a
            # particular embodiment rather than a generic assistant.
            "body_context_installed": (codex_home / "AGENTS.md").is_file(),
        },
        "hermes": {
            "present": hermes_home.is_dir(),
            "version": hermes_version,
            "home_exists": hermes_home.is_dir(),
            "env_file_exists": (hermes_home / ".env").is_file(),
        },
    }


def inspect_enrollments(home: Path) -> dict[str, Any]:
    """Existing Matrix bodies here, so onboarding resumes rather than duplicates.

    Reads public bundle data only. Custody files are counted and named; they are never
    opened, and no key, password or capability material is reported.
    """

    state_root = home / ".local" / "state" / "daimon-matrix"
    bodies: list[dict[str, Any]] = []
    retired: list[str] = []
    if state_root.is_dir():
        bundle_paths: list[Path] = []
        seen: set[Path] = set()
        for pattern in STATE_ROOT_GLOBS:
            for candidate in sorted(state_root.glob(pattern)):
                if candidate not in seen:
                    seen.add(candidate)
                    bundle_paths.append(candidate)
        for bundle_path in bundle_paths:
            root = bundle_path.parent
            try:
                bundle = json.loads(bundle_path.read_bytes())
                origin = bundle["local_origin"]
                manifest = bundle["manifest"]
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                bodies.append(
                    {
                        "state_root": str(root),
                        "readable": False,
                        "reason": "bundle_unreadable_or_malformed",
                    }
                )
                continue
            custody = sorted(
                path.name
                for path in root.iterdir()
                if path.is_file()
                and (
                    path.name.endswith("custody.json")
                    or path.name.endswith(".password")
                    or path.name.endswith("client.key")
                    or path.name.endswith("capability.key")
                )
            )
            bodies.append(
                {
                    "state_root": str(root),
                    "readable": True,
                    "principal_id": origin.get("principal_id"),
                    "body_ref": origin.get("body_ref"),
                    "being_ref": manifest.get("being_ref"),
                    "manifest_revision": manifest.get("revision"),
                    "embodiment_count": len(manifest.get("embodiments") or []),
                    "peer_listen_configured": bool(
                        (bundle.get("peer_transport") or {}).get("enabled")
                    ),
                    # A live daemon holds its socket; its presence is evidence a body
                    # may already be running here, which onboarding must not disturb.
                    "daemon_socket_present": (root / "matrix.sock").exists(),
                    "custody_file_names": custody,
                }
            )
        # A retirement record is a directory on some hosts and a plain JSON file
        # on others; both are durable evidence a body was withdrawn, so both are
        # reported.
        retired = sorted(
            path.name
            for path in state_root.iterdir()
            if path.name.startswith("RETIRED-")
        )
    config_root = home / ".config" / "daimon-matrix"
    password_files = (
        sorted(
            str(path.relative_to(config_root))
            for path in config_root.rglob("*password*")
            if path.is_file()
        )
        if config_root.is_dir()
        else []
    )
    return {
        "state_root_exists": state_root.is_dir(),
        "bodies": bodies,
        "retired_state_roots": retired,
        # Paths relative to the config root, never contents. Their names tell the
        # operator whether custody exists without putting a single byte of it in a
        # report that is meant to be pasted into a public issue.
        "custody_password_file_paths": password_files,
        "resumable": any(body.get("readable") for body in bodies),
    }


def inspect_tools() -> dict[str, Any]:
    missing_required = [name for name in REQUIRED_TOOLS if shutil.which(name) is None]
    missing_recommended = [
        name for name in RECOMMENDED_TOOLS if shutil.which(name) is None
    ]
    return {
        "present": sorted(
            name
            for name in (*REQUIRED_TOOLS, *RECOMMENDED_TOOLS)
            if shutil.which(name) is not None
        ),
        "missing_required": [
            {"tool": name, "needed_for": REQUIRED_TOOLS[name]}
            for name in missing_required
        ],
        "missing_recommended": [
            {"tool": name, "needed_for": RECOMMENDED_TOOLS[name]}
            for name in missing_recommended
        ],
    }


def inspect_neutral_territory(home: Path) -> dict[str, Any]:
    """Whether the harness-neutral surface exists on this host."""

    agents = home / ".agents"
    skills = agents / "skills"
    memory_root = agents / "memory"
    pools = (
        sorted(path.name for path in memory_root.iterdir() if path.is_dir())
        if memory_root.is_dir()
        else []
    )
    return {
        "agents_root_exists": agents.is_dir(),
        "skills_root_exists": skills.is_dir(),
        "memory_pools": pools,
        # Named, not counted: a pool without library.db is not a working memory base.
        "pools_with_library": sorted(
            name
            for name in pools
            if (memory_root / name / "agent-memory" / "library.db").is_file()
        ),
    }


def probe_routes(home: Path) -> dict[str, Any]:
    """Opt-in. Interface names and reachability, never addresses."""

    non_loopback: list[str] = []
    try:
        output = subprocess.run(
            [sys.executable, "-c", _INTERFACE_PROBE],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if output.returncode == 0:
            non_loopback = [
                name
                for name in output.stdout.split()
                if name and not name.startswith("lo")
            ]
    except (OSError, subprocess.SubprocessError):
        pass
    live_units: list[str] = []
    if SUPPORTED_PLATFORMS.get(
        (platform.system().lower(), platform.machine().lower())
    ) == ("linux-systemd"):
        listing = _run(
            [
                "systemctl",
                "--user",
                "list-units",
                "daimon*",
                "--state=active",
                "--no-legend",
            ]
        )
        if listing:
            live_units = sorted(
                {line.split()[0] for line in listing.splitlines() if line.split()}
            )
    return {
        "non_loopback_interface_names": sorted(set(non_loopback)),
        "has_non_loopback_route": bool(non_loopback),
        "active_daimon_user_units": live_units,
        "bodies_with_live_socket": sorted(
            {
                str(path.parent)
                for pattern in SOCKET_GLOBS
                for path in (home / ".local" / "state" / "daimon-matrix").glob(pattern)
            }
        ),
    }


_INTERFACE_PROBE = """
import socket, struct, fcntl, array
names = []
try:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for index in range(256):
            packed = struct.pack("i", index)
            try:
                name = fcntl.ioctl(probe.fileno(), 0x8913, packed)
            except OSError:
                continue
    finally:
        probe.close()
except Exception:
    pass
try:
    for name_entry in socket.if_nameindex():
        names.append(name_entry[1])
except Exception:
    pass
print(" ".join(names))
"""


def verdict(report: dict[str, Any]) -> tuple[str, list[str]]:
    """One verdict and the exact preparations standing between here and onboarding."""

    reasons: list[str] = []
    preparations: list[str] = []
    if not report["platform"]["supported"]:
        # Only the platform shape is genuinely unsupported: this project has not
        # onboarded it and is not claiming to. Everything else below is work the
        # operator can do on a host that is otherwise fine.
        reasons.append(str(report["platform"]["reason"]))
    if not report["python"]["supported"]:
        preparations.append(
            f"install an interpreter in {report['python']['interval']}: "
            f"{report['python']['reason']}"
        )
    for row in report["tools"]["missing_required"]:
        preparations.append(f"install {row['tool']}: {row['needed_for']}")
    for row in report["tools"]["missing_recommended"]:
        preparations.append(f"recommended, install {row['tool']}: {row['needed_for']}")
    harnesses = report["harnesses"]
    if not (harnesses["codex"]["present"] or harnesses["hermes"]["present"]):
        preparations.append(
            "no harness present: onboarding attaches Matrix to an existing daimon, it "
            "does not create one"
        )
    if (
        harnesses["codex"]["present"]
        and not harnesses["codex"]["body_context_installed"]
    ):
        preparations.append(
            "codex is present but has no body AGENTS.md, so a session here "
            "would not know which embodiment it is"
        )
    if not report["neutral_territory"]["agents_root_exists"]:
        preparations.append(
            "no harness-neutral territory (~/.agents): memory and skills would be "
            "harness-private, and what gets promoted there is an owner decision"
        )
    for body in report["enrollments"]["bodies"]:
        if not body.get("readable", True):
            reasons.append(
                f"existing state root is unreadable or malformed: {body['state_root']}"
            )
    if report["enrollments"]["resumable"]:
        preparations.append(
            "an enrollment already exists on this host: resume it, do not mint "
            "a second being for the same daimon"
        )
    if reasons:
        return VERDICT_UNSUPPORTED, reasons + preparations
    if preparations:
        return VERDICT_PREPARATION, preparations
    return VERDICT_COMPATIBLE, []


def audit(home: Path, *, probe: bool) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "home": str(home),
        "platform": inspect_platform(),
        "python": inspect_python(),
        "harnesses": inspect_harnesses(home),
        "enrollments": inspect_enrollments(home),
        "tools": inspect_tools(),
        "neutral_territory": inspect_neutral_territory(home),
        "probe": probe_routes(home) if probe else None,
    }
    decision, preparations = verdict(report)
    report["verdict"] = decision
    report["preparations"] = preparations
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--home",
        type=Path,
        default=Path.home(),
        help="the owner home to inspect; defaults to this process's home",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="also report interface names and whether a body is already live here",
    )
    arguments = parser.parse_args(argv)
    report = audit(arguments.home, probe=arguments.probe)
    sys.stdout.write(json.dumps(report, indent=1, sort_keys=True) + "\n")
    return 0 if report["verdict"] == VERDICT_COMPATIBLE else 1


if __name__ == "__main__":
    raise SystemExit(main())
