"""Private archive round trips using real files, SQLite/WAL and hostile archives."""

from __future__ import annotations

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
            b"-----BEGIN PRIVATE KEY-----",
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
