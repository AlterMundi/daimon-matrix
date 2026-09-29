"""Read-only onboarding preflight: it must see every body shape that exists.

The failure this suite guards is specific and expensive. A preflight that cannot
see an existing enrollment reports zero bodies, and an operator reading that mints
a second being for a daimon who already has one. A body activated by
``daimon-rebirth`` keeps its runtime one directory deeper than a hand-hosted body,
so both shapes have to be found, and the report has to stay pasteable into a
public issue: no custody contents and no network addresses.
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import tempfile
import unittest
from typing import Any

from tools.preflight_onboarding import (
    PYTHON_MAXIMUM_EXCLUSIVE,
    PYTHON_MINIMUM,
    REPORT_SCHEMA,
    SOCKET_GLOBS,
    STATE_ROOT_GLOBS,
    VERDICT_COMPATIBLE,
    VERDICT_PREPARATION,
    VERDICT_UNSUPPORTED,
    audit,
    inspect_enrollments,
    inspect_python,
    probe_routes,
    verdict,
)
from tools.preflight_onboarding import main as preflight_main

BEING = "dm:being:v1:" + "A" * 43
KEY_SENTINEL = "PRIVATE-KEY-BLOCKS-MUST-NEVER-BE-PRINTED"
PASSWORD_SENTINEL = "sentinel-passphrase-must-never-be-printed"
IPV4 = re.compile(r"(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![\d.])")


def _bundle(
    principal: str, *, revision: int = 6, embodiments: int = 3
) -> dict[str, Any]:
    return {
        "local_origin": {
            "principal_id": principal,
            "body_ref": f"codex:test:{principal}",
        },
        "manifest": {
            "being_ref": BEING,
            "revision": revision,
            "embodiments": [{"n": index} for index in range(embodiments)],
        },
        "peer_transport": {"enabled": True},
    }


def _state_root(home: pathlib.Path) -> pathlib.Path:
    root = home / ".local" / "state" / "daimon-matrix"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write_body(
    home: pathlib.Path, name: str, principal: str, *, rebirth: bool
) -> pathlib.Path:
    """Lay out a body the way each of the two real installation paths does."""

    body = _state_root(home) / name
    runtime = body / "package" / "runtime" if rebirth else body / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    (runtime / "runtime.json").write_text(
        json.dumps(_bundle(principal)), encoding="utf-8"
    )
    return runtime


def _report(**overrides: Any) -> dict[str, Any]:
    """A synthetic report, so verdict logic is tested without this host's shape."""

    report: dict[str, Any] = {
        "platform": {"supported": True, "reason": None},
        "python": {"supported": True, "interval": ">=3.11,<3.14", "reason": None},
        "tools": {"missing_required": [], "missing_recommended": []},
        "harnesses": {
            "codex": {"present": True, "body_context_installed": True},
            "hermes": {"present": False},
        },
        "neutral_territory": {"agents_root_exists": True},
        "enrollments": {"bodies": [], "resumable": False},
    }
    report.update(overrides)
    return report


class EnrollmentDiscoveryTests(unittest.TestCase):
    def test_rebirth_layout_body_is_found(self) -> None:
        """The regression: package/runtime is a real shape and used to be invisible."""

        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            _write_body(home, "compaii-codex", "compaii.codex@test", rebirth=True)

            found = inspect_enrollments(home)

        self.assertEqual(1, len(found["bodies"]))
        body = found["bodies"][0]
        self.assertEqual("compaii.codex@test", body["principal_id"])
        self.assertEqual(6, body["manifest_revision"])
        self.assertTrue(body["readable"])

    def test_hand_hosted_layout_body_is_found(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            _write_body(home, "compaii-chat", "compaii-chat@test", rebirth=False)

            found = inspect_enrollments(home)

        self.assertEqual(1, len(found["bodies"]))
        self.assertEqual("compaii-chat@test", found["bodies"][0]["principal_id"])

    def test_both_layouts_found_without_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            _write_body(home, "hand", "hand@test", rebirth=False)
            _write_body(home, "rebirth", "rebirth@test", rebirth=True)

            found = inspect_enrollments(home)

        principals = sorted(body["principal_id"] for body in found["bodies"])
        self.assertEqual(["hand@test", "rebirth@test"], principals)

    def test_rebirth_layout_makes_host_resumable(self) -> None:
        """An unseen body means resumable=False, which is how duplicates get minted."""

        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            _write_body(home, "compaii-codex", "compaii.codex@test", rebirth=True)

            found = inspect_enrollments(home)
            decision, preparations = verdict(
                _report(
                    enrollments={
                        "bodies": found["bodies"],
                        "resumable": found["resumable"],
                    }
                )
            )

        self.assertTrue(found["resumable"])
        self.assertEqual(VERDICT_PREPARATION, decision)
        self.assertTrue(
            any("do not mint" in line for line in preparations),
            preparations,
        )

    def test_malformed_bundle_is_reported_not_silently_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runtime = _write_body(home, "broken", "broken@test", rebirth=True)
            (runtime / "runtime.json").write_text("{not json", encoding="utf-8")

            found = inspect_enrollments(home)

        self.assertEqual(1, len(found["bodies"]))
        self.assertFalse(found["bodies"][0]["readable"])
        self.assertEqual("bundle_unreadable_or_malformed", found["bodies"][0]["reason"])
        self.assertFalse(found["resumable"])

    def test_retired_records_include_files_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            root = _state_root(home)
            (root / "RETIRED-daimon-v0.1.0rc1.json").write_text("{}", encoding="utf-8")
            (root / "RETIRED-older-body").mkdir()

            found = inspect_enrollments(home)

        self.assertEqual(
            ["RETIRED-daimon-v0.1.0rc1.json", "RETIRED-older-body"],
            found["retired_state_roots"],
        )

    def test_custody_is_named_by_relative_path_and_never_by_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runtime = _write_body(
                home, "compaii-codex", "compaii.codex@test", rebirth=True
            )
            (runtime / "client.key").write_text(KEY_SENTINEL, encoding="utf-8")
            config = home / ".config" / "daimon-matrix" / "dm-test"
            config.mkdir(parents=True, exist_ok=True)
            (config / "body.password").write_text(PASSWORD_SENTINEL, encoding="utf-8")

            found = inspect_enrollments(home)
            rendered = json.dumps(found, sort_keys=True)

        self.assertIn("client.key", found["bodies"][0]["custody_file_names"])
        self.assertEqual(
            ["dm-test/body.password"], found["custody_password_file_paths"]
        )
        self.assertNotIn(KEY_SENTINEL, rendered)
        self.assertNotIn(PASSWORD_SENTINEL, rendered)


class ProbeTests(unittest.TestCase):
    def test_live_socket_found_in_both_layouts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            hand = _write_body(home, "hand", "hand@test", rebirth=False)
            rebirth = _write_body(home, "rebirth", "rebirth@test", rebirth=True)
            (hand / "matrix.sock").write_text("", encoding="utf-8")
            (rebirth / "matrix.sock").write_text("", encoding="utf-8")

            found = sorted(probe_routes(home)["bodies_with_live_socket"])

        self.assertEqual([str(hand), str(rebirth)], found)

    def test_socket_globs_cover_every_state_root_glob(self) -> None:
        """A runtime shape that is enumerated must also be probed for liveness."""

        self.assertEqual(
            sorted(
                path.replace("runtime.json", "matrix.sock") for path in STATE_ROOT_GLOBS
            ),
            sorted(SOCKET_GLOBS),
        )


class VerdictTests(unittest.TestCase):
    def test_clean_supported_host_is_compatible(self) -> None:
        decision, preparations = verdict(_report())

        self.assertEqual(VERDICT_COMPATIBLE, decision)
        self.assertEqual([], preparations)

    def test_unsupported_is_reserved_for_platform_shape(self) -> None:
        decision, reasons = verdict(
            _report(platform={"supported": False, "reason": "not a pilot shape"})
        )

        self.assertEqual(VERDICT_UNSUPPORTED, decision)
        self.assertIn("not a pilot shape", reasons)

    def test_missing_tool_is_preparation_not_unsupported(self) -> None:
        decision, preparations = verdict(
            _report(
                tools={
                    "missing_required": [
                        {"tool": "git", "needed_for": "fetch release"}
                    ],
                    "missing_recommended": [],
                }
            )
        )

        self.assertEqual(VERDICT_PREPARATION, decision)
        self.assertIn("install git: fetch release", preparations)

    def test_missing_body_context_is_preparation(self) -> None:
        decision, preparations = verdict(
            _report(
                harnesses={
                    "codex": {"present": True, "body_context_installed": False},
                    "hermes": {"present": False},
                }
            )
        )

        self.assertEqual(VERDICT_PREPARATION, decision)
        self.assertTrue(any("AGENTS.md" in line for line in preparations), preparations)

    def test_unreadable_state_root_is_a_hard_stop(self) -> None:
        decision, reasons = verdict(
            _report(
                enrollments={
                    "bodies": [
                        {
                            "readable": False,
                            "state_root": "/tmp/broken/runtime",
                            "reason": "bundle_unreadable_or_malformed",
                        }
                    ],
                    "resumable": False,
                }
            )
        )

        self.assertEqual(VERDICT_UNSUPPORTED, decision)
        self.assertTrue(any("/tmp/broken/runtime" in line for line in reasons), reasons)


class ReportShapeTests(unittest.TestCase):
    def test_python_interval_matches_constants(self) -> None:
        result = inspect_python()

        self.assertEqual(
            f">={PYTHON_MINIMUM[0]}.{PYTHON_MINIMUM[1]},"
            f"<{PYTHON_MAXIMUM_EXCLUSIVE[0]}.{PYTHON_MAXIMUM_EXCLUSIVE[1]}",
            result["interval"],
        )
        self.assertEqual(result["supported"], result["reason"] is None)

    def test_probe_is_off_by_default_and_prints_no_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)
            runtime = _write_body(
                home, "compaii-codex", "compaii.codex@test", rebirth=True
            )
            (runtime / "client.key").write_text(KEY_SENTINEL, encoding="utf-8")
            (runtime / "matrix.sock").write_text("", encoding="utf-8")
            buffer = io.StringIO()

            with contextlib.redirect_stdout(buffer):
                exit_code = preflight_main(["--home", str(home), "--probe"])

        report = json.loads(buffer.getvalue())
        self.assertEqual(1, exit_code)
        self.assertEqual(REPORT_SCHEMA, report["schema"])
        self.assertIsNotNone(report["probe"])
        self.assertEqual(1, len(report["enrollments"]["bodies"]))
        self.assertEqual(1, len(report["probe"]["bodies_with_live_socket"]))
        self.assertNotIn(KEY_SENTINEL, buffer.getvalue())
        self.assertIsNone(IPV4.search(buffer.getvalue()))

    def test_audit_does_not_probe_unless_asked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = pathlib.Path(temporary)

            report = audit(home, probe=False)

        self.assertIsNone(report["probe"])


if __name__ == "__main__":
    unittest.main()
