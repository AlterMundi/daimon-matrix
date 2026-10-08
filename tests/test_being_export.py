"""Private archive round trips using real files, SQLite/WAL and hostile archives."""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from tools import export_being as tool

BLANK_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwg"
    "JC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIy"
    "MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QA"
    "HwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIh"
    "MUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVW"
    "V1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXG"
    "x8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQF"
    "BgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAV"
    "YnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOE"
    "hYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq"
    "8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q=="
)


class BeingExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.archive = self.root / "being.tgz"

    def put(self, relative: str, raw: bytes, root: Path | None = None) -> Path:
        target = (root or self.source) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        return target

    def plan(self, kind: str = "hermes") -> dict:
        return tool.discover("Fixture", [(kind, self.source)])

    def pack(self, plan: dict | None = None, archive: Path | None = None) -> dict:
        return tool.export(
            plan or self.plan(), archive or self.archive, writers_stopped=True
        )

    def staged(self) -> tuple[Path, dict]:
        destination = self.root / "received"
        tool.verify(self.archive, destination=destination)
        return destination, json.loads((destination / "manifest.json").read_bytes())

    def hostile(self, entries: list[tuple[str, bytes]], *, link: bool = False) -> None:
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, raw in entries:
                info = tarfile.TarInfo(name)
                if link:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../../escape"
                    archive.addfile(info)
                else:
                    info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))

    def selection(
        self,
        include: list[str],
        omit: list[dict[str, str]] | None = None,
        *,
        sqlite_ownership: str = "same-being",
        kind: str = "hermes",
    ) -> dict:
        return {
            "schema": tool.SELECTION_SCHEMA,
            "being_label": "Fixture",
            "sources": [
                {
                    "kind": kind,
                    "root": str(self.source),
                    "selection": {
                        "include": include,
                        "omit": omit or [],
                        "ownership": "same-being",
                        "sqlite_ownership": sqlite_ownership,
                    },
                }
            ],
        }

    def test_code_reference_and_blank_jpeg_round_trip_without_content_changes(
        self,
    ) -> None:
        source = b"api_key = provider_configuration.resolve_active_provider_key\n"
        self.put("provider.py", source)
        self.put("blank.jpg", BLANK_JPEG)
        self.assertTrue(tool.TOKEN.search(BLANK_JPEG))
        self.pack()
        target, _ = self.staged()
        for name, raw in (("provider.py", source), ("blank.jpg", BLANK_JPEG)):
            self.assertEqual((self.source / name).read_bytes(), raw)
            self.assertEqual((target / "payload/hermes-001" / name).read_bytes(), raw)

    def test_python_reference_classification_never_hides_literals_or_other_formats(
        self,
    ) -> None:
        for name, raw in (
            ("literal.py", b'api_key = "actualSyntheticCredential123456789"\n'),
            (
                "resolver.py",
                b"api_key = provider_configuration.lookup("
                b'"actualSyntheticCredential123456789")\n',
            ),
            ("broken.py", b"api_key = actualSyntheticCredential123456789\ninvalid(\n"),
            (
                "comment.py",
                b"api_key = provider_configuration.resolve(\n"
                b" # password = actualSyntheticCredential123456789\n)\n",
            ),
            ("settings.txt", b"api_key = actualSyntheticCredential123456789\n"),
            (
                "history.json",
                b'{"text":"api_key = actualSyntheticCredential123456789"}',
            ),
            (
                "code.py",
                b"api_key = provider_configuration.current_key\n"
                b'password = "actualSyntheticCredential123456789"\n',
            ),
        ):
            with self.subTest(name=name):
                path = self.put(name, raw)
                with self.assertRaisesRegex(tool.ExportError, "embedded_credential"):
                    tool.scan_credentials(path)

    def test_jpeg_credentials_outside_exact_public_tables_remain_rejected(self) -> None:
        secret = b"sk-" + b"a" * 40
        comment = b"\xff\xfe" + (len(secret) + 2).to_bytes(2, "big") + secret
        modified = bytearray(BLANK_JPEG)
        # Keep the token-like symbol run, alter another symbol in its table.
        table = modified.index(b"\xff\xc4\x00\xb5")
        modified[table + 22] ^= 1
        for raw in (
            BLANK_JPEG + secret,
            BLANK_JPEG[:2] + comment + BLANK_JPEG[2:],
            bytes(modified),
            BLANK_JPEG[2:],
        ):
            with self.subTest(bytes=len(raw)):
                path = self.put("image.jpg", raw)
                with self.assertRaisesRegex(tool.ExportError, "embedded_credential"):
                    tool.scan_credentials(path)

    def test_binary_sqlite_history_still_requires_credential_safe_handoff(self) -> None:
        path = self.source / "history.db"
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("CREATE TABLE messages(text)")
            connection.execute("INSERT INTO messages VALUES (?)", ("sk-" + "a" * 40,))
            connection.commit()
        original = path.read_bytes()
        with self.assertRaisesRegex(tool.ExportError, "embedded_credential"):
            self.pack()
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(self.archive.exists())

    def test_unapproved_profiles_fail_before_foreign_traversal(self) -> None:
        self.put("SOUL.md", b"selected default body")
        self.put("profiles/Other/SOUL.md", b"unrelated private context")
        visited = []
        original_walk = os.walk

        def watching_walk(*args, **kwargs):
            for result in original_walk(*args, **kwargs):
                visited.append(Path(result[0]))
                yield result

        with (
            patch.object(tool.os, "walk", watching_walk),
            self.assertRaisesRegex(tool.ExportError, "profiles_require_explicit"),
        ):
            self.plan()
        self.assertEqual(visited, [self.source])
        self.assertFalse(self.archive.exists())

    def test_multi_profile_round_trip_preserves_owned_roots_without_foreign_reads(
        self,
    ) -> None:
        expected = {
            "SOUL.md": b"selected identity",
            "AGENTS.md": b"useful operating behavior",
            "config.yaml": b"theme: green\n",
            "history/old.txt": b"old lived context",
            "profiles/Owned/SOUL.md": b"same being, historical body",
            "profiles/Owned/history/older.txt": b"its history",
        }
        for path, raw in expected.items():
            self.put(path, raw)
        self.put(".env", b"HERMES_TUI=1\n")
        foreign = self.source / "profiles/Other"
        self.put("profiles/Other/SOUL.md", b"unrelated private context")
        self.put("profiles/Other/.env", b'CREDENTIALS=(\n "private component"\n)\n')
        selection = self.selection(
            [".", "profiles/Owned"],
            [{"path": "profiles/Other", "reason": "another being; outside handoff"}],
        )
        original_open = Path.open

        def guarded_open(path, *args, **kwargs):
            if foreign == path or foreign in path.parents:
                raise AssertionError("foreign content must not be opened")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", guarded_open):
            plan = tool.discover_selection(selection)
            self.pack(plan)
            destination, manifest = self.staged()
        for path, raw in expected.items():
            self.assertEqual(
                (destination / "payload/hermes-001" / path).read_bytes(), raw
            )
            self.assertEqual((self.source / path).read_bytes(), raw)
        self.assertEqual(
            (destination / "payload/hermes-001/.env.nonsecret").read_bytes(),
            b"HERMES_TUI=1\n",
        )
        self.assertFalse((destination / "payload/hermes-001/profiles/Other").exists())
        self.assertEqual(
            manifest["sources"][0]["selection"], selection["sources"][0]["selection"]
        )
        self.assertEqual(len(manifest["sources"][0]["omissions"]), 2)
        self.assertIn("owner declaration", manifest["sources"][0]["ownership_evidence"])

    def test_select_root_files_and_owned_subtree_records_unselected_frontier(
        self,
    ) -> None:
        self.put("SOUL.md", b"identity")
        self.put("AGENTS.md", b"useful behavior")
        self.put("history/old.txt", b"retained history")
        self.put("profiles/Other/secret.txt", b"outside scope")
        self.put(".env", b'CREDENTIALS=(\n "private component"\n)\n')
        plan = tool.discover_selection(
            self.selection(["SOUL.md", "AGENTS.md", "history"])
        )
        self.pack(plan)
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 3)
        self.assertEqual(
            {
                entry["path"]: entry["reason"]
                for entry in manifest["sources"][0]["omissions"]
            },
            {
                ".env": "outside_explicit_context_selection",
                "profiles": "outside_explicit_context_selection",
            },
        )

    def test_explicitly_omitted_dotenv_is_not_derived_or_read(self) -> None:
        self.put("SOUL.md", b"identity")
        original = self.put(".env", b'CREDENTIALS=(\n "private component"\n)\n')
        plan = tool.discover_selection(
            self.selection(
                ["."], [{"path": ".env", "reason": "body-private configuration"}]
            )
        )
        self.pack(plan)
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 1)
        self.assertTrue(original.exists())

    def test_profile_anchors_are_required_and_new_unapproved_profile_is_rejected(
        self,
    ) -> None:
        self.put("SOUL.md", b"identity")
        self.put("profiles/Owned/SOUL.md", b"same being")
        with self.assertRaisesRegex(tool.ExportError, "explicit_anchor"):
            tool.discover_selection(self.selection(["."]))
        plan = tool.discover_selection(self.selection([".", "profiles/Owned"]))
        self.put("profiles/New/SOUL.md", b"unapproved profile")
        with self.assertRaisesRegex(tool.ExportError, "explicit_anchor"):
            self.pack(plan)
        self.assertFalse(self.archive.exists())

    def test_whole_profile_boundary_can_be_omitted_without_traversal(self) -> None:
        self.put("SOUL.md", b"identity")
        self.put("profiles/Other/SOUL.md", b"outside scope")
        plan = tool.discover_selection(
            self.selection(
                ["."], [{"path": "profiles", "reason": "outside same-being context"}]
            )
        )
        self.pack(plan)
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 1)
        self.assertEqual(manifest["sources"][0]["omissions"][0]["path"], "profiles")

    def test_selected_and_unselected_root_additions_still_require_new_plan(
        self,
    ) -> None:
        self.put("SOUL.md", b"identity")
        self.put("history/old.txt", b"old memory")
        for new in ("history/new.txt", "new-unselected.txt"):
            plan = tool.discover_selection(self.selection(["SOUL.md", "history"]))
            path = self.put(new, b"new context")
            with self.assertRaisesRegex(tool.ExportError, "source_drift"):
                self.pack(plan)
            path.unlink()
        self.assertFalse(self.archive.exists())

    def test_explicit_sqlite_ownership_boundary_keeps_complete_rows_or_refuses(
        self,
    ) -> None:
        original = self.source / "sessions.db"
        with closing(sqlite3.connect(original)) as connection:
            connection.execute("CREATE TABLE history(origin TEXT, text TEXT)")
            connection.executemany(
                "INSERT INTO history VALUES (?, ?)",
                [
                    ("old body", "historical context"),
                    ("current body", "recent context"),
                ],
            )
            connection.commit()
        original_hash = tool.digest(original)
        for ownership in ("mixed", "unknown"):
            with self.assertRaisesRegex(tool.ExportError, "ownership_adapter"):
                tool.discover_selection(
                    self.selection(["."], sqlite_ownership=ownership)
                )
        self.pack(tool.discover_selection(self.selection(["."])))
        _, manifest = self.staged()
        self.assertEqual(manifest["files"][0]["sqlite"]["table_counts"]["history"], 2)
        self.assertEqual(tool.digest(original), original_hash)

    def test_file_only_sqlite_selection_tracks_wal_drift_in_earlier_root(self) -> None:
        path = self.source / "library.db"
        connection = sqlite3.connect(path)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE memories(text TEXT)")
        connection.execute("INSERT INTO memories VALUES ('earlier memory')")
        connection.commit()
        later = self.root / "later"
        self.put("history.txt", b"later context", later)
        document = self.selection(["library.db"])
        document["sources"].append(
            {
                "kind": "context",
                "root": str(later),
                "selection": self.selection(["."])["sources"][0]["selection"],
            }
        )
        plan = tool.discover_selection(document)
        wal = next(
            item
            for item in plan["sources"][0]["omissions"]
            if item["path"].endswith("-wal")
        )
        self.assertIn("mtime_ns", wal)
        original_copy = tool.copy_source

        def changing_copy(source: Path, target: Path):
            result = original_copy(source, target)
            if source.parent == later:
                connection.execute("INSERT INTO memories VALUES ('new memory in WAL')")
                connection.commit()
            return result

        with (
            patch.object(tool, "copy_source", changing_copy),
            self.assertRaisesRegex(tool.ExportError, "source_changed"),
        ):
            self.pack(plan)
        self.assertFalse(self.archive.exists())
        self.assertEqual(
            connection.execute("SELECT count(*) FROM memories").fetchone()[0], 2
        )

    def test_selected_sqlite_sidecar_cannot_be_foreign_or_a_link(self) -> None:
        path = self.source / "library.db"
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE memories(text TEXT)")
        connection.commit()
        with self.assertRaisesRegex(tool.ExportError, "sidecar_conflicts"):
            tool.discover_selection(
                self.selection(
                    ["library.db"],
                    [{"path": "library.db-wal", "reason": "foreign data"}],
                )
            )
        connection.close()
        external = self.root / "outside-wal"
        external.write_bytes(b"unrelated context")
        (self.source / "library.db-wal").symlink_to(external)
        with self.assertRaisesRegex(
            tool.ExportError, "sidecar_dependency_must_be_regular"
        ):
            tool.discover_selection(self.selection(["library.db"]))
        self.assertEqual(external.read_bytes(), b"unrelated context")

    def test_shared_skills_do_not_copy_body_bindings_or_known_custody(self) -> None:
        self.put("helper/SKILL.md", b"portable useful behavior")
        self.put("binding/runtime.json", b"sk-" + b"a" * 40)
        self.put("runtime/private.bin", b"body-private runtime")
        self.put("custody.json", b"opaque custody fixture")
        self.put("unknown-opaque.dat", b"arbitrarily named encrypted custody fixture")
        document = self.selection(
            ["."],
            [
                {"path": "binding", "reason": "body-private binding"},
                {"path": "runtime", "reason": "signed body-private runtime"},
                {"path": "unknown-opaque.dat", "reason": "owner-identified custody"},
            ],
            kind="skills",
        )
        document["sources"][0]["selection"]["ownership"] = "shared-commons"
        self.pack(tool.discover_selection(document))
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 1)
        self.assertEqual(len(manifest["sources"][0]["omissions"]), 4)

    def test_selection_validates_paths_missing_anchors_and_conflicts(self) -> None:
        self.put("SOUL.md", b"identity")
        for included, omitted in (
            (["../escape"], []),
            (["absent"], []),
            (["SOUL.md"], [{"path": "../escape", "reason": "outside scope"}]),
            (["SOUL.md"], [{"path": "SOUL.md", "reason": "conflicting choice"}]),
        ):
            with self.assertRaises(tool.ExportError):
                tool.discover_selection(self.selection(included, omitted))

    def test_project_runtime_is_useful_context_not_a_body_binding(self) -> None:
        self.put("runtime/worker.py", b"print('useful project runtime')\n")
        self.pack(self.plan("project"))
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 1)

    def test_cli_selection_discovery_export_and_unpack(self) -> None:
        self.put("SOUL.md", b"identity")
        self.put("profiles/Other/SOUL.md", b"outside scope")
        document = self.selection(
            ["."], [{"path": "profiles", "reason": "other beings"}]
        )
        selection = self.root / "selection.json"
        selection.write_bytes(tool.json_bytes(document))
        plan = self.root / "plan.json"
        script = str(Path(tool.__file__))
        for arguments in (
            ["discover", "--selection", str(selection), "--output", str(plan)],
            [
                "export",
                "--plan",
                str(plan),
                "--writers-stopped",
                "--output",
                str(self.archive),
            ],
            ["verify", "--archive", str(self.archive)],
            [
                "unpack",
                "--archive",
                str(self.archive),
                "--destination",
                str(self.root / "received"),
            ],
        ):
            process = subprocess.run(
                [sys.executable, script, *arguments], capture_output=True, text=True
            )
            self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(
            (self.root / "received/payload/hermes-001/SOUL.md").read_bytes(),
            b"identity",
        )
        direct = self.root / "direct.zip"
        process = subprocess.run(
            [
                sys.executable,
                script,
                "export",
                "--selection",
                str(selection),
                "--writers-stopped",
                "--output",
                str(direct),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(tool.verify(direct)["verified"])

    def test_complete_selected_memory_and_historical_skill_bytes_round_trip(
        self,
    ) -> None:
        expected = {
            "SOUL.md": b"Origin and evolving self definition\n",
            "memories/LOGOS.md": b"Pulse\n",
            "agent-memory/history/old-2001.txt": b"An old, meaningful experience\n",
            "agent-memory/backups/old.snapshot": b"Retained original\n",
            "agent-memory/attachments/unknown.bin": b"\x00\x01\x02",
            "skills/private/scripts/tool.py": b"print('useful behavior')\n",
            "skills/private/history/v1/SKILL.md": b"First learned version\n",
            "unknown-extension/learned-state.json": b'{"remember":"all"}\n',
        }
        for name, raw in expected.items():
            self.put(name, raw)
        original = {name: tool.digest(self.source / name) for name in expected}
        report = self.pack()
        destination, manifest = self.staged()
        self.assertEqual(report["files"], len(expected))
        for name, raw in expected.items():
            self.assertEqual(
                (destination / "payload/hermes-001" / name).read_bytes(), raw
            )
            self.assertEqual(tool.digest(self.source / name), original[name])
        self.assertEqual(manifest["target_adoption"], "not_performed")
        self.assertTrue(all(entry["delta"] == "unknown" for entry in manifest["files"]))

    def test_mixed_harnesses_and_multiple_pools_never_overlay(self) -> None:
        roots = []
        for index, kind in enumerate(("codex", "hermes", "memory", "memory")):
            root = self.root / f"root-{index}"
            root.mkdir()
            self.put("history.txt", f"origin-{index}".encode(), root)
            roots.append((kind, root))
        self.pack(tool.discover("Eko fixture", roots))
        destination, manifest = self.staged()
        self.assertEqual(len(manifest["sources"]), 4)
        for index, source in enumerate(manifest["sources"]):
            self.assertEqual(
                (destination / "payload" / source["id"] / "history.txt").read_bytes(),
                f"origin-{index}".encode(),
            )

    def test_all_sqlite_databases_snapshot_including_wal_nested_history(self) -> None:
        self.source.joinpath("history").mkdir()
        for relative in ("library.db", "history/other.sqlite3"):
            path = self.source / relative
            connection = sqlite3.connect(path)
            self.addCleanup(connection.close)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                "CREATE TABLE memories(id INTEGER PRIMARY KEY, text TEXT)"
            )
            connection.execute("CREATE TABLE empty_table(id INTEGER)")
            connection.executemany(
                "INSERT INTO memories VALUES (?,?)", [(1, "old"), (2, "new")]
            )
            connection.commit()
            self.assertTrue(Path(str(path) + "-wal").exists())
        self.pack(self.plan("memory"))
        destination, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 2)
        for entry in manifest["files"]:
            self.assertEqual(entry["sqlite"]["table_counts"]["memories"], 2)
            self.assertEqual(entry["sqlite"]["table_counts"]["empty_table"], 0)
            with closing(sqlite3.connect(destination / entry["path"])) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT text FROM memories ORDER BY id"
                    ).fetchall(),
                    [("old",), ("new",)],
                )
        self.assertTrue(manifest["sources"][0]["omissions"])

    def test_baseline_delta_preserves_originals_even_when_unchanged(self) -> None:
        baseline = self.root / "baseline"
        baseline.mkdir()
        for name, raw in {
            "same.txt": b"default",
            "changed.txt": b"before",
            "removed.txt": b"removed",
        }.items():
            self.put(name, raw, baseline)
        for name, raw in {
            "same.txt": b"default",
            "changed.txt": b"after",
            "added.txt": b"learned",
        }.items():
            self.put(name, raw)
        plan = tool.discover(
            "Fixture", [("hermes", self.source)], {"hermes-001": baseline}
        )
        self.pack(plan)
        _, manifest = self.staged()
        self.assertEqual(
            {e["relative_path"]: e["delta"] for e in manifest["files"]},
            {"same.txt": "unchanged", "changed.txt": "modified", "added.txt": "added"},
        )
        self.assertEqual(manifest["sources"][0]["absent_from_source"], ["removed.txt"])
        self.assertTrue(
            next(e for e in manifest["files"] if e["delta"] == "unchanged")[
                "baseline_sha256"
            ]
        )

    def test_authorized_native_sessions_and_projects_remain_raw_origin_data(
        self,
    ) -> None:
        self.put("rollout.jsonl", b'{"origin":"codex","unfinished":"continue"}\n')
        self.pack(tool.discover("Fixture", [("sessions", self.source)]))
        destination, manifest = self.staged()
        self.assertEqual(manifest["native_session_resume"], "not_performed")
        self.assertTrue((destination / "payload/sessions-001/rollout.jsonl").is_file())

    def test_known_secret_files_are_omitted_and_reported_without_values(self) -> None:
        self.put("auth.json", b'{"private":"not for export"}')
        self.put(".env", b"SENSITIVE=hidden")
        self.put("SOUL.md", b"identity")
        self.pack()
        _, manifest = self.staged()
        self.assertEqual(len(manifest["files"]), 2)
        self.assertEqual(
            {entry["path"] for entry in manifest["sources"][0]["omissions"]},
            {"auth.json", ".env"},
        )
        self.assertNotIn("not for export", json.dumps(manifest))

    def test_useful_dotenv_behavior_survives_without_provider_credentials(self) -> None:
        token = "sk-" + "a" * 40
        original = self.put(".env", f"HERMES_TUI=1\nOPENAI_API_KEY={token}\n".encode())
        original_raw = original.read_bytes()
        self.put("SOUL.md", b"identity")
        self.pack()
        destination, manifest = self.staged()
        env = destination / "payload/hermes-001/.env.nonsecret"
        self.assertIn("HERMES_TUI=1", env.read_text())
        self.assertNotIn(token, env.read_text())
        self.assertEqual(original.read_bytes(), original_raw)
        entry = next(e for e in manifest["files"] if e.get("derivation"))
        self.assertEqual(entry["private_variable_names"], ["OPENAI_API_KEY"])

    def test_multiline_private_dotenv_never_leaks_remaining_value(self) -> None:
        # Synthetic body only, no real key material.
        raw = (
            b'PRIVATE_KEY="private first line\nprivate remaining lines\n"\n'
            b"HERMES_TUI=1\n"
        )
        original = self.put(".env", raw)
        self.put("SOUL.md", b"identity")
        with self.assertRaisesRegex(tool.ExportError, "multiline_environment"):
            self.pack()
        self.assertFalse(self.archive.exists())
        self.assertEqual(original.read_bytes(), raw)

    def test_private_environment_continuations_and_expressions_are_not_evaluated(
        self,
    ) -> None:
        for raw in (
            b"API_KEY=firstline\\\nsecondline\n",
            b"PRIVATE_KEY=$(cat <<EOF\nremaining private data\nEOF\n",
            b'CREDENTIALS=(\n "private fixture component"\n)\n',
            b'declare -a CREDENTIALS=(\n "private fixture component"\n)\n',
            b'CREDENTIALS+=(\n "private fixture component"\n)\n',
        ):
            self.put(".env", raw)
            self.put("SOUL.md", b"identity")
            with self.assertRaises(tool.ExportError):
                self.pack()
            self.assertFalse(self.archive.exists())

    def test_embedded_credential_refuses_whole_export_without_mutating_memory(
        self,
    ) -> None:
        raw = b"learned text\n" + b"sk-" + b"a" * 40
        path = self.put("old-memory.txt", raw)
        with self.assertRaisesRegex(tool.ExportError, "embedded_credential"):
            self.pack()
        self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(self.archive.exists())

    def test_private_key_and_chunk_boundary_token_are_detected(self) -> None:
        for raw in (
            b"-----BEGIN" + b" PRIVATE KEY-----",
            b" " * (1024 * 1024 - 2) + b"sk-" + b"a" * 40,
        ):
            self.put("identity.txt", raw)
            with self.assertRaises(tool.ExportError):
                self.pack()

    def test_no_export_without_declared_writer_quiescence(self) -> None:
        self.put("SOUL.md", b"identity")
        with self.assertRaisesRegex(tool.ExportError, "writer_quiescence"):
            tool.export(self.plan(), self.archive, writers_stopped=False)

    def test_credentials_in_continuity_metadata_are_not_archived(self) -> None:
        self.put("SOUL.md", b"identity")
        plan = self.plan()
        plan["continuity_notes"] = "sk-" + "a" * 40
        with self.assertRaisesRegex(tool.ExportError, "embedded_credential"):
            self.pack(plan)
        self.assertFalse(self.archive.exists())

    def test_source_drift_after_discovery_refuses(self) -> None:
        self.put("SOUL.md", b"before")
        plan = self.plan()
        self.put("SOUL.md", b"after-longer")
        with self.assertRaisesRegex(tool.ExportError, "source_drift"):
            self.pack(plan)
        self.assertFalse(self.archive.exists())

    def test_new_file_during_export_refuses_incomplete_packet(self) -> None:
        self.put("SOUL.md", b"identity")
        original_copy = tool.copy_source

        def changing_copy(source: Path, destination: Path):
            result = original_copy(source, destination)
            self.put("new-memory.txt", b"arrived during export")
            return result

        with (
            patch.object(tool, "copy_source", changing_copy),
            self.assertRaisesRegex(tool.ExportError, "source_changed"),
        ):
            self.pack()
        self.assertFalse(self.archive.exists())

    def test_earlier_root_changed_while_copying_later_root_is_detected(self) -> None:
        self.put("SOUL.md", b"identity")
        later = self.root / "later"
        later.mkdir()
        self.put("history.txt", b"later context", later)
        plan = tool.discover("Fixture", [("hermes", self.source), ("context", later)])
        original_copy = tool.copy_source

        def changing_copy(source: Path, destination: Path):
            result = original_copy(source, destination)
            if source.parent == later:
                self.put("new-memory.txt", b"arrived after first root was checked")
            return result

        with (
            patch.object(tool, "copy_source", changing_copy),
            self.assertRaisesRegex(tool.ExportError, "source_changed"),
        ):
            self.pack(plan)
        self.assertFalse(self.archive.exists())

    def test_sqlite_wal_only_changes_are_not_labeled_unchanged(self) -> None:
        baseline = self.root / "baseline"
        baseline.mkdir()
        reference = baseline / "library.db"
        with closing(sqlite3.connect(reference)) as connection:
            connection.execute("CREATE TABLE memories(text TEXT)")
            connection.commit()
        original = self.source / "library.db"
        shutil.copyfile(reference, original)
        connection = sqlite3.connect(original)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO memories VALUES ('new lived experience')")
        connection.commit()
        plan = tool.discover(
            "Fixture", [("memory", self.source)], {"memory-001": baseline}
        )
        self.pack(plan)
        _, manifest = self.staged()
        entry = manifest["files"][0]
        self.assertEqual(entry["delta"], "unknown")
        self.assertEqual(entry["sqlite"]["table_counts"]["memories"], 1)

    def test_wal_only_write_in_earlier_root_is_detected(self) -> None:
        path = self.source / "library.db"
        connection = sqlite3.connect(path)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE memories(text TEXT)")
        connection.commit()
        later = self.root / "later"
        later.mkdir()
        self.put("context.txt", b"later root", later)
        plan = tool.discover("Fixture", [("memory", self.source), ("context", later)])
        original_copy = tool.copy_source

        def changing_copy(source: Path, destination: Path):
            result = original_copy(source, destination)
            if source.parent == later:
                connection.execute("INSERT INTO memories VALUES ('new memory in WAL')")
                connection.commit()
            return result

        with (
            patch.object(tool, "copy_source", changing_copy),
            self.assertRaisesRegex(tool.ExportError, "source_changed"),
        ):
            self.pack(plan)
        self.assertFalse(self.archive.exists())

    def test_baseline_symlinks_are_reported_without_reading_external_bytes(
        self,
    ) -> None:
        baseline = self.root / "baseline"
        baseline.mkdir()
        external = self.root / "outside.txt"
        external.write_bytes(b"outside baseline scope")
        (baseline / "SOUL.md").symlink_to(external)
        self.put("SOUL.md", b"identity")
        plan = tool.discover(
            "Fixture", [("hermes", self.source)], {"hermes-001": baseline}
        )
        self.pack(plan)
        _, manifest = self.staged()
        self.assertIsNone(manifest["files"][0]["baseline_sha256"])
        self.assertEqual(
            manifest["sources"][0]["baseline_omissions"][0]["reason"],
            "unresolved_symlink",
        )

    def test_symlink_is_reported_and_source_outside_scope_is_not_read(self) -> None:
        external = self.root / "external.txt"
        external.write_bytes(b"unrelated private data")
        (self.source / "link").symlink_to(external)
        self.put("SOUL.md", b"identity")
        self.pack()
        _, manifest = self.staged()
        self.assertEqual(
            manifest["sources"][0]["omissions"][0]["reason"], "unresolved_symlink"
        )
        self.assertEqual(len(manifest["files"]), 1)

    def test_private_output_staging_and_no_live_executable_activation(self) -> None:
        source = self.put("hooks/run.sh", b"#!/bin/sh\nexit 0\n")
        source.chmod(0o755)
        self.pack()
        destination, manifest = self.staged()
        self.assertEqual(stat.S_IMODE(self.archive.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertTrue(manifest["files"][0]["executable"])
        self.assertEqual(
            stat.S_IMODE((destination / manifest["files"][0]["path"]).stat().st_mode),
            0o600,
        )

    def test_existing_output_and_destination_are_never_overwritten(self) -> None:
        self.put("SOUL.md", b"identity")
        self.pack()
        before = self.archive.read_bytes()
        with self.assertRaises(tool.ExportError):
            self.pack()
        destination = self.root / "received"
        destination.mkdir()
        (destination / "keep").write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            tool.verify(self.archive, destination=destination)
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertEqual((destination / "keep").read_bytes(), b"existing")

    def test_reject_traversal_links_duplicates_unknown_schema_extra_members(
        self,
    ) -> None:
        for entries, link in (
            ([("../escape", b"bad")], False),
            ([("payload/link", b"")], True),
            ([("manifest.json", b"{}"), ("manifest.json", b"{}")], False),
            ([("manifest.json", b'{"schema":"future"}')], False),
            (
                [
                    (
                        "manifest.json",
                        tool.json_bytes({"schema": tool.ARCHIVE_SCHEMA, "files": []}),
                    ),
                    ("payload/extra", b"unlisted"),
                ],
                False,
            ),
        ):
            self.hostile(entries, link=link)
            with self.assertRaises(tool.ExportError):
                tool.verify(self.archive, destination=self.root / "received")
            self.assertFalse((self.root / "received").exists())
            self.assertFalse((self.root / "escape").exists())

    def test_zip_round_trip_and_link_refusal(self) -> None:
        self.put("SOUL.md", b"identity")
        archive = self.root / "being.zip"
        self.pack(archive=archive)
        self.assertTrue(tool.verify(archive)["verified"])
        with zipfile.ZipFile(archive, "w") as zipped:
            info = zipfile.ZipInfo("payload/link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(info, "../../escape")
        with self.assertRaises(tool.ExportError):
            tool.verify(archive)

    def test_corrupt_payload_refuses_before_any_extraction(self) -> None:
        self.put("SOUL.md", b"identity")
        self.pack()
        with tarfile.open(self.archive) as archive:
            manifest = archive.extractfile("manifest.json").read()
        self.hostile(
            [("manifest.json", manifest), ("payload/hermes-001/SOUL.md", b"corrupted")]
        )
        with self.assertRaisesRegex(tool.ExportError, "mismatch"):
            tool.verify(self.archive, destination=self.root / "received")
        self.assertFalse((self.root / "received").exists())

    def test_archive_hash_and_resource_limits(self) -> None:
        self.put("SOUL.md", b"identity")
        self.pack()
        with self.assertRaisesRegex(tool.ExportError, "sha256_mismatch"):
            tool.verify(self.archive, expected_sha256="0" * 64)
        with self.assertRaisesRegex(tool.ExportError, "resource_limit"):
            tool.verify(self.archive, max_bytes=1)

    def test_cli_automatic_mixed_export_and_verify_use_no_harness_or_provider(
        self,
    ) -> None:
        owner_home = self.root / "owner"
        self.put(".hermes/SOUL.md", b"Hermes origin", owner_home)
        self.put(".codex/AGENTS.md", b"Current Codex context", owner_home)
        self.put(
            ".agents/skills/helper/SKILL.md", b"Shared useful behavior", owner_home
        )
        script = Path(tool.__file__)
        command = [
            sys.executable,
            str(script),
            "export",
            "--being",
            "Fixture",
            "--harness",
            "mixed",
            "--source-home",
            str(owner_home),
            "--writers-stopped",
            "--output",
            str(self.archive),
        ]
        env = {
            **os.environ,
            "OPENAI_API_KEY": "",
            "CODEX_HOME": str(self.root / "unused"),
        }
        process = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)["verified"])
        _, manifest = self.staged()
        self.assertEqual(
            {s["kind"] for s in manifest["sources"]}, {"hermes", "codex", "skills"}
        )
        self.assertFalse((self.root / "unused").exists())


if __name__ == "__main__":
    unittest.main()
