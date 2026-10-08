from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing, contextmanager
from pathlib import Path

from tools import export_being as archive
from tools import preserve_memory as tool


@contextmanager
def connection(path):
    with closing(sqlite3.connect(path)) as db, db:
        yield db


class PreservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.learning = self.root / "learning"
        self.learning.mkdir()
        self.content = b"Original attributed observation."
        self.sha = hashlib.sha256(self.content).hexdigest()
        (self.source / "statement.txt").write_bytes(self.content)
        self.asset = b"\x00\x01Selected fixture resource bytes"
        self.asset_sha = hashlib.sha256(self.asset).hexdigest()
        (self.source / "resource.bin").write_bytes(self.asset)
        self.reference = {
            "sha256": self.sha,
            "byte_length": len(self.content),
            "media_type": "text/plain",
            "classification": "personal",
        }
        with connection(self.source / "library.db") as db:
            db.executescript(
                "CREATE TABLE chapters(id,raw,unknown); "
                "CREATE TABLE chapter_revisions(id,raw);"
            )
            db.execute(
                "INSERT INTO chapters VALUES(1,'corrected outcome',?)", (b"\x01\x02",)
            )
            db.execute("INSERT INTO chapter_revisions VALUES(1,'original outcome')")
        with connection(self.source / "ledger.db") as db:
            db.execute(
                "CREATE TABLE events(event_id,status,event_json,kind,inserted_order)"
            )
            db.execute(
                "INSERT INTO events VALUES(?,?,?,?,?)",
                (
                    "fixture:event",
                    "known",
                    json.dumps(
                        {
                            "payload": {
                                "content_ref": self.reference,
                                "evidence_refs": ["fixture:older-event"],
                            }
                        }
                    ),
                    "memory.recorded",
                    1,
                ),
            )
        self.git("init", "-q")
        for text in ("earlier learned method", "current learned method"):
            (self.learning / "lesson.md").write_text(text)
            self.git("add", "lesson.md")
            self.git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                text,
            )
        self.first = self.git("rev-parse", "HEAD~1")
        self.plan = archive.discover(
            "Fixture", [("memory", self.source), ("context", self.learning)]
        )
        self.selection = {
            "schema": tool.SELECTION,
            "hmk": [{"source_id": "memory-001", "path": "library.db"}],
            "matrix": [{"source_id": "memory-001", "path": "ledger.db"}],
            "content": {
                self.sha: {"source_id": "memory-001", "path": "statement.txt"},
                self.asset_sha: {"source_id": "memory-001", "path": "resource.bin"},
            },
            "required_content": [
                {
                    "sha256": self.asset_sha,
                    "byte_length": len(self.asset),
                    "media_type": "application/octet-stream",
                }
            ],
            "artifacts": [
                {
                    "source_id": "context-002",
                    "path": "lesson.md",
                    "role": "native-learned-artifact",
                }
            ],
            "git_sources": ["context-002"],
            "world_references": ["https://example.invalid/issue/47"],
            "future_extension": {"unknown": ["retain", 42]},
        }
        self.profile = self.root / "profile"

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.learning), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def stage(self) -> Path:
        tool.build(self.plan, self.selection, self.profile, writers_stopped=True)
        plan = archive.discover(
            "Fixture",
            [
                ("memory", self.source),
                ("context", self.learning),
                ("context", self.profile),
            ],
        )
        archive.export(plan, self.root / "transport.tgz", writers_stopped=True)
        result = self.root / "received"
        archive.verify(self.root / "transport.tgz", destination=result)
        return result

    def verify(self, stage: Path) -> dict:
        return tool.verify(stage, "payload/context-003/memory-preservation.json")

    def test_transport_without_sources_retains_history_unknown_fields_and_git(
        self,
    ) -> None:
        stage = self.stage()
        before = tool.database_state(self.source / "library.db")
        shutil.rmtree(self.source)
        shutil.rmtree(self.learning)
        result = self.verify(stage)
        self.assertTrue(result["complete_available_content"])
        self.assertEqual(
            before, tool.database_state(stage / "payload/memory-001/library.db")
        )
        profile = json.loads(
            (stage / "payload/context-003/memory-preservation.json").read_bytes()
        )
        self.assertEqual(
            profile["selection"]["future_extension"], self.selection["future_extension"]
        )
        received_git = self.root / "restored-git"
        subprocess.run(
            [
                "git",
                "clone",
                "--bare",
                str(stage / "payload/context-003/context-002.bundle"),
                str(received_git),
            ],
            check=True,
            capture_output=True,
        )
        old = subprocess.run(
            ["git", "-C", str(received_git), "show", self.first + ":lesson.md"],
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(old, b"earlier learned method")
        self.assertFalse(
            (received_git / "config").read_text().find(str(self.learning)) >= 0
        )

    def test_missing_required_dependency_blocks_build_and_leaves_no_profile(
        self,
    ) -> None:
        self.selection["content"] = {}
        with self.assertRaisesRegex(
            tool.PreservationError, "required_content_unresolved"
        ):
            tool.build(self.plan, self.selection, self.profile, writers_stopped=True)
        self.assertFalse(self.profile.exists())

    def test_missing_or_altered_received_dependency_is_not_prior_unavailability(
        self,
    ) -> None:
        stage = self.stage()
        p = stage / "payload/memory-001/statement.txt"
        p.unlink()
        with self.assertRaisesRegex(
            tool.PreservationError, "preserved_member_mismatch"
        ):
            self.verify(stage)
        p.write_bytes(b"Altered observation")
        with self.assertRaisesRegex(
            tool.PreservationError, "preserved_member_mismatch"
        ):
            self.verify(stage)
        p.write_bytes(self.content)
        self.assertTrue(self.verify(stage)["complete_available_content"])
        self.assertEqual(self.verify(stage), self.verify(stage))

    def test_prior_unavailability_is_explicit_and_not_complete_content(self) -> None:
        self.selection["content"].pop(self.sha)
        self.selection["unavailable"] = {
            self.sha: {
                "status": "unavailable_before_export",
                "reason": "Fixture source never supplied these referenced bytes.",
            }
        }
        stage = self.stage()
        result = self.verify(stage)
        self.assertTrue(result["preservation_verified"])
        self.assertFalse(result["complete_available_content"])
        self.assertEqual(result["unavailable_before_export"], 1)

    def test_changed_history_and_source_drift_are_detected(self) -> None:
        stage = self.stage()
        with connection(stage / "payload/memory-001/library.db") as db:
            db.execute("DELETE FROM chapter_revisions")
        with self.assertRaisesRegex(
            tool.PreservationError, "preserved_member_mismatch"
        ):
            self.verify(stage)
        (self.source / "statement.txt").write_bytes(b"changed source")
        other = self.root / "other-profile"
        with self.assertRaisesRegex(
            tool.PreservationError, "source_drift_regenerate_plan"
        ):
            tool.build(self.plan, self.selection, other, writers_stopped=True)

    def test_profile_cannot_be_modified_or_selected_outside_scope(self) -> None:
        stage = self.stage()
        p = stage / "payload/context-003/memory-preservation.json"
        p.write_text(p.read_text() + " ")
        with self.assertRaisesRegex(
            tool.PreservationError, "profile_not_bound_to_archive"
        ):
            self.verify(stage)
        self.selection["content"][self.sha]["path"] = "../outside"
        with self.assertRaises(archive.ExportError):
            tool.build(
                self.plan, self.selection, self.root / "other", writers_stopped=True
            )

    def test_git_pack_hook_cannot_execute(self) -> None:
        marker = self.root / "executed"
        self.git("config", "pack.packObjectsHook", "touch " + str(marker))
        self.assertTrue(self.verify(self.stage())["preservation_verified"])
        self.assertFalse(marker.exists())
