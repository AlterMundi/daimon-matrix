"""Real archives, coherent memory copies and receiving context without live bodies."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import closing, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools import export_being as exporter
from tools import install_codex_identity as installer
from tools import receive_being as receiver


class BeingReceivingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.put("SOUL.md", b"I am Fixture. Ani and Sai are my tribe.\n")
        self.put("AGENTS.md", b"Historical project-only release bureaucracy.\n")
        self.put("history/old.jsonl", b'{"origin":"hermes","text":"old encounter"}\n')
        self.put(
            "skills/listening/SKILL.md",
            b"---\nname: listening\n---\nRemember people.\n",
        )
        self.put("skills/listening/tool.py", b"# preserved executable behavior\n")
        (self.source / "skills/listening/tool.py").chmod(0o700)
        self.database = self.source / "agent-memory/library.db"
        self.database.parent.mkdir()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE TABLE chapters (id TEXT PRIMARY KEY, text TEXT)")
            connection.executemany(
                "INSERT INTO chapters VALUES (?, ?)",
                [("old", "An old relationship"), ("new", "A recent commitment")],
            )
            connection.commit()
        self.archive = self.root / "being.tgz"
        self.output = self.root / "received"

    def put(self, relative: str, raw: bytes) -> None:
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def pack(self) -> tuple[str, dict]:
        result = exporter.export(
            exporter.discover("Fixture", [("hermes", self.source)]),
            self.archive,
            writers_stopped=True,
        )
        return result["sha256"], receiver.discover(self.archive, result["sha256"])

    def prepare(self, **kwargs) -> dict:
        digest, selection = self.pack()
        return receiver.prepare(self.archive, digest, selection, self.output, **kwargs)

    def chapters(self, path: Path) -> list[tuple[str, str]]:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
            return connection.execute(
                "SELECT id, text FROM chapters ORDER BY id"
            ).fetchall()

    def test_preserved_originals_working_memory_and_actual_codex_install(self) -> None:
        archive_hash, selection = self.pack()
        foundation = self.root / "selected-foundation.md"
        foundation.write_text(
            "Selected Source principles; Fixture's identity remains its own."
        )
        result = receiver.prepare(
            self.archive, archive_hash, selection, self.output, foundation=foundation
        )
        self.assertTrue(result["prepared"])
        original = self.output / "originals/payload/hermes-001/agent-memory/library.db"
        working = self.output / "memory/store-001/library.db"
        self.assertEqual(self.chapters(original), self.chapters(working))
        with closing(sqlite3.connect(working)) as connection:
            connection.execute(
                "INSERT INTO chapters VALUES ('later', 'New receiving memory')"
            )
            connection.commit()
        self.assertEqual(len(self.chapters(working)), 3)
        self.assertEqual(len(self.chapters(original)), 2)
        self.assertEqual(len(self.chapters(self.database)), 2)
        self.assertEqual(exporter.digest(self.archive), archive_hash)
        self.assertEqual(exporter.digest(self.output / "source.archive"), archive_hash)
        index = json.loads((self.output / "continuity-index.json").read_bytes())
        self.assertEqual(
            index["native_resume"], "not_imported; retain source harness origin"
        )
        self.assertIn("history/old.jsonl", str(index["files"]))
        self.assertEqual(
            (self.output / "skills/skill-001/tool.py").stat().st_mode & 0o777, 0o700
        )
        codex_home = self.root / "ordinary-codex"
        codex_home.mkdir()
        (codex_home / "config.toml").write_text('model = "existing"\n')
        for name in ("auth.json", "history.jsonl"):
            (codex_home / name).write_bytes(b"existing private native state")
        context = self.output / "context"
        args = argparse.Namespace(
            codex_home=codex_home,
            identity_file=context / "IDENTITY.md",
            soul=context / "SOUL.md",
            foundation=context / "FOUNDATION.md",
            memory_access=context / "MEMORY-ACCESS.md",
            model="selected",
            reasoning="medium",
            approval="on-request",
            sandbox="workspace-write",
            apply=True,
        )
        self.assertTrue(installer.install(args)["applied"])
        loaded = (codex_home / "AGENTS.md").read_text()
        self.assertIn("I am Fixture. Ani and Sai are my tribe.", loaded)
        self.assertIn("Selected Source principles", loaded)
        self.assertNotIn("Historical project-only release bureaucracy", loaded)
        self.assertIn("enrollment remains pending", loaded)
        for name in ("auth.json", "history.jsonl"):
            self.assertEqual(
                (codex_home / name).read_bytes(), b"existing private native state"
            )

    def test_manual_hmk_runs_only_on_request_and_uses_working_copy(self) -> None:
        scripts = self.root / "trusted native scripts"
        scripts.mkdir()
        marker = self.root / "manual-call.json"
        (scripts / "memoryctl.py").write_text(
            "import json, os, sqlite3, sys\n"
            "from pathlib import Path\n"
            "from contextlib import closing\n"
            f"marker = Path({str(marker)!r})\n"
            "with closing(sqlite3.connect(os.environ['HMK_DB_PATH'])) as connection:\n"
            "    query = 'SELECT id, text FROM chapters ORDER BY id'\n"
            "    rows = connection.execute(query).fetchall()\n"
            "marker.write_text(json.dumps({'args':sys.argv[1:], 'rows':rows, "
            "'base':os.environ['HMK_AGENT_MEMORY_BASE']}))\n"
        )
        with patch(
            "subprocess.run", side_effect=AssertionError("implicit native call")
        ):
            result = self.prepare(hmk_python=Path(sys.executable), hmk_scripts=scripts)
        self.assertTrue(result["native_hmk_bound"])
        self.assertFalse(marker.exists())
        wrapper = self.output / "commands/hmk-store-001.py"
        literal = "old relation; $(do-not-execute) `do-not-execute`"
        environment = dict(os.environ, HMK_DB_PATH=str(self.root / "wrong.db"))
        subprocess.run(
            [
                sys.executable,
                str(wrapper),
                "memoryctl.py",
                "hybrid-pack",
                "--query",
                literal,
            ],
            env=environment,
            check=True,
            capture_output=True,
        )
        report = json.loads(marker.read_text())
        self.assertEqual(report["args"], ["hybrid-pack", "--query", literal])
        self.assertEqual(len(report["rows"]), 2)
        self.assertEqual(report["base"], str(self.output / "memory/store-001"))
        marker.unlink()
        refused = subprocess.run(
            [sys.executable, str(wrapper), "../memoryctl.py"], capture_output=True
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(marker.exists())

    def test_owner_selected_receiving_soul_and_partial_coverage_preserve_source(
        self,
    ) -> None:
        digest, selection = self.pack()
        soul = self.root / "reconciled.md"
        soul.write_text("Fixture's reconciled identity and chosen Source ancestry.\n")
        receiver.prepare(
            self.archive, digest, selection, self.output, receiving_soul=soul
        )
        self.assertEqual(
            (self.output / "context/SOUL.md").read_bytes(), soul.read_bytes()
        )
        original = self.output / "originals/payload/hermes-001/SOUL.md"
        self.assertEqual(original.read_bytes(), (self.source / "SOUL.md").read_bytes())
        report = json.loads((self.output / "preparation.json").read_bytes())
        self.assertEqual(report["memory_coverage"], "owner-selected")
        self.assertFalse(report["matrix_enrolled"])
        self.assertFalse(report["providers_called"])
        self.assertEqual(report["memory_runtime_acceptance"], "not_performed")

    def test_multiple_souls_require_actual_selection(self) -> None:
        self.put("history/SOUL.md", b"An older preserved self-definition.")
        digest, selection = self.pack()
        self.assertIsNone(selection["soul"])
        with self.assertRaisesRegex(
            receiver.ReceivingError, "select_one_preserved_soul"
        ):
            receiver.prepare(self.archive, digest, selection, self.output)
        self.assertFalse((self.output / "preparation.json").exists())
        self.assertTrue((self.output / "originals/manifest.json").exists())

    def test_existing_preparation_never_overwrites_later_memory(self) -> None:
        digest, selection = self.pack()
        receiver.prepare(self.archive, digest, selection, self.output)
        marker = self.output / "receiving-work.txt"
        marker.write_text("already useful later work")
        with self.assertRaises(FileExistsError):
            receiver.prepare(self.archive, digest, selection, self.output)
        self.assertEqual(marker.read_text(), "already useful later work")

    def test_wrong_hash_and_unsafe_selections_never_become_ready(self) -> None:
        digest, selection = self.pack()
        with self.assertRaisesRegex(exporter.ExportError, "archive_sha256_mismatch"):
            receiver.prepare(self.archive, "0" * 64, selection, self.output)
        for index, change in enumerate(
            (
                {"memory_coverage": "inferred"},
                {"being_label": "Different"},
                {
                    "memory": [
                        {
                            "name": "../escape",
                            "path": "payload/hermes-001/agent-memory",
                            "database": "library.db",
                        }
                    ]
                },
                {"skills": [{"name": "escape", "path": "../escape"}]},
                {"memory": selection["memory"] * 2},
                {"soul": "outside/SOUL.md"},
            )
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                receiver.prepare(
                    self.archive,
                    digest,
                    {**selection, **change},
                    self.root / f"bad-{index}",
                )
            self.assertFalse((self.root / f"bad-{index}/preparation.json").exists())
        self.assertFalse((self.root / "escape").exists())

    def test_nonsecret_environment_stays_preserved_without_live_config_adoption(
        self,
    ) -> None:
        self.put(".env", b"HERMES_TUI=1\n")
        self.prepare()
        self.assertEqual(
            (self.output / "originals/payload/hermes-001/.env.nonsecret").read_bytes(),
            b"HERMES_TUI=1\n",
        )
        self.assertNotIn(
            "HERMES_TUI", (self.output / "context/AGENTS.preview.md").read_text()
        )

    def test_known_credentials_in_a_self_consistent_archive_are_refused(self) -> None:
        digest, selection = self.pack()
        with tarfile.open(self.archive) as archive:
            members = {}
            for info in archive:
                with archive.extractfile(info) as stream:
                    members[info.name] = stream.read()
        manifest = json.loads(members["manifest.json"])
        raw = b"synthetic account credentials: retained separately"
        name = "payload/hermes-001/auth.json"
        manifest["files"].append(
            {
                "path": name,
                "source_id": "hermes-001",
                "relative_path": "auth.json",
                "kind": "hermes",
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
        members[name] = raw
        members["manifest.json"] = exporter.json_bytes(manifest)
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, raw in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        digest = exporter.digest(self.archive)
        exporter.verify(self.archive, expected_sha256=digest)
        with self.assertRaisesRegex(receiver.ReceivingError, "credential_member"):
            receiver.prepare(self.archive, digest, selection, self.output)
        self.assertFalse((self.output / "preparation.json").exists())

    def test_symlink_and_special_inputs_are_refused_without_following(self) -> None:
        digest, selection = self.pack()
        link = self.root / "linked.tgz"
        link.symlink_to(self.archive)
        with self.assertRaisesRegex(exporter.ExportError, "symlink"):
            receiver.prepare(link, digest, selection, self.output)
        fifo = self.root / "not-an-archive"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(receiver.ReceivingError, "bounded_regular"):
            receiver.prepare(fifo, digest, selection, self.output)
        self.assertFalse(self.output.exists())

    def test_oversize_soul_is_preserved_but_not_reported_installable(self) -> None:
        self.put("SOUL.md", b"full preserved context\n" * 2000)
        digest, selection = self.pack()
        with self.assertRaisesRegex(ValueError, "exceeds_native_bound"):
            receiver.prepare(self.archive, digest, selection, self.output)
        original = self.output / "originals/payload/hermes-001/SOUL.md"
        self.assertEqual(original.read_bytes(), (self.source / "SOUL.md").read_bytes())
        self.assertFalse((self.output / "preparation.json").exists())

    def test_zip_round_trip_and_owner_only_preparation(self) -> None:
        self.archive = self.root / "being.zip"
        self.prepare()
        for path in self.output.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o077)

    def test_cli_error_contains_no_private_source_path(self) -> None:
        _digest, selection = self.pack()
        selection_path = self.root / "private-selection.json"
        selection_path.write_bytes(exporter.json_bytes(selection))
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = receiver.main(
                [
                    "prepare",
                    "--archive",
                    str(self.archive),
                    "--sha256",
                    "0" * 64,
                    "--selection",
                    str(selection_path),
                    "--output",
                    str(self.output),
                ]
            )
        self.assertEqual(result, 1)
        self.assertNotIn(str(self.root), stdout.getvalue())
        self.assertEqual(
            json.loads(stdout.getvalue())["error"], "archive_sha256_mismatch"
        )

    def test_missing_sqlite_module_cli_refuses_without_private_diagnostics(
        self,
    ) -> None:
        _digest, selection = self.pack()
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("CREATE VIRTUAL TABLE special USING fts5(text)")
            connection.execute("PRAGMA writable_schema=ON")
            connection.execute(
                "UPDATE sqlite_master SET sql=replace(sql, 'fts5', ?) "
                "WHERE name='special'",
                ("private_fixture_native_module",),
            )
            connection.commit()
        # This models a valid export from an engine with an additional module
        # installed, received by an engine without that module. Keep archive
        # membership/hash internally coherent; receiving SQLite must refuse.
        with tarfile.open(self.archive) as archive:
            members = {}
            for info in archive:
                with archive.extractfile(info) as stream:
                    members[info.name] = stream.read()
        manifest = json.loads(members["manifest.json"])
        database_name = "payload/hermes-001/agent-memory/library.db"
        raw = self.database.read_bytes()
        for entry in manifest["files"]:
            if entry["path"] == database_name:
                entry.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        members[database_name] = raw
        members["manifest.json"] = exporter.json_bytes(manifest)
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, raw in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        selection_path = self.root / "selected.json"
        selection_path.write_bytes(exporter.json_bytes(selection))
        result = subprocess.run(
            [
                sys.executable,
                "tools/receive_being.py",
                "prepare",
                "--archive",
                str(self.archive),
                "--sha256",
                exporter.digest(self.archive),
                "--selection",
                str(selection_path),
                "--output",
                str(self.output),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout)["error"], "sqlite_incompatible_or_corrupt"
        )
        self.assertNotIn("private_fixture_native_module", result.stdout)
        self.assertNotIn(str(self.root), result.stdout)
        self.assertFalse((self.output / "preparation.json").exists())


if __name__ == "__main__":
    unittest.main()
