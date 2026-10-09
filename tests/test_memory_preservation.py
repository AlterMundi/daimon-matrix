from __future__ import annotations

import copy
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

    def test_unsafe_source_identity_cannot_overwrite_unrelated_bundle(self) -> None:
        marker = self.root / "outside-profile.bundle"
        marker.write_bytes(b"unrelated existing work")
        for source_id in ("../outside-profile", "nested/source", "/outside-profile"):
            with self.subTest(source_id=source_id):
                plan = copy.deepcopy(self.plan)
                plan["sources"][1]["id"] = source_id
                selection = copy.deepcopy(self.selection)
                selection["git_sources"] = [source_id]
                with self.assertRaises(archive.ExportError):
                    tool.build(plan, selection, self.profile, writers_stopped=True)
                self.assertEqual(marker.read_bytes(), b"unrelated existing work")
                self.assertFalse(self.profile.exists())
        plan = copy.deepcopy(self.plan)
        plan["sources"][1]["kind"] = "unsupported"
        with self.assertRaisesRegex(archive.ExportError, "invalid_source"):
            tool.build(plan, self.selection, self.profile, writers_stopped=True)
        with self.assertRaisesRegex(
            tool.PreservationError, "unique_nonempty_sources_required"
        ):
            tool.build(
                {**self.plan, "sources": []},
                self.selection,
                self.profile,
                writers_stopped=True,
            )
        self.assertEqual(marker.read_bytes(), b"unrelated existing work")
        self.assertFalse(self.profile.exists())

    def test_git_pack_hook_cannot_execute(self) -> None:
        marker = self.root / "executed"
        self.git("config", "pack.packObjectsHook", "touch " + str(marker))
        self.assertTrue(self.verify(self.stage())["preservation_verified"])
        self.assertFalse(marker.exists())


def qualify_current_hmk(self):
    """Offline end-to-end tool fixture called by the opt-in SDK qualifier."""
    import os
    import time

    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.identity import verify_genesis
    from daimon_matrix.ledger import Ledger
    from daimon_matrix.memory_projection import (
        HMK_COMMIT,
        MemoryProjectionAdapter,
        MemoryProjectionError,
        ProjectionJournal,
        create_projection_profile,
    )
    from daimon_matrix.weave import BeingManifest, RootAuthority, verify_event
    from tests.test_dm034_memory_projection import (
        CURRENT_HMK_COMMIT,
        MEMORY_ID,
        NOW,
        HMKCLITransport,
    )
    from tools import preserve_memory as preservation

    started = time.monotonic()
    corpus = os.environ.get("HMK_PRESERVATION_CORPUS")
    if corpus:
        archive.copy_source(Path(corpus), self.transport.database)
    else:
        self.transport.memoryctl(
            "add-text",
            "--shelf",
            "library",
            "--title",
            "Native learned lesson",
            "--raw",
            "An observed failed invitation is not a delivered invitation.",
        )
    original_state = preservation.database_state(self.transport.database)
    native_tables = (
        "chapters",
        "chapter_revisions",
        "chapter_links",
    )
    with closing(sqlite3.connect(self.transport.database)) as db:
        native = {
            name: db.execute("SELECT * FROM " + name).fetchall()
            for name in native_tables
        }
    asserted, plan = self.record(label="portable-assert", text="Three units recovered.")
    corrected, _corrected_plan = self.record(
        label="portable-correct",
        operation="correct",
        text="Two recovered; the third remained lost.",
        predecessor=asserted,
        predecessor_decision_id=plan["decision_id"],
    )
    retracted_id = "34000000-0000-4000-8000-000000000097"
    doomed, doomed_plan = self.record(
        label="portable-doomed",
        memory_id=retracted_id,
        text="An obsolete attributed statement.",
    )
    retracted, _ = self.record(
        label="portable-retract",
        memory_id=retracted_id,
        operation="retract",
        text=None,
        predecessor=doomed,
        predecessor_decision_id=doomed_plan["decision_id"],
    )
    active_id = "34000000-0000-4000-8000-000000000099"
    active, _ = self.record(
        label="portable-active",
        memory_id=active_id,
        text="A previous body learned a sensor skill; this body has no sensor.",
    )
    source = self.root_path / "selected-context"
    source.mkdir(mode=0o700)
    archive.copy_source(
        self.root_path / "legion/ledger.sqlite", source / "ledger.sqlite"
    )
    public = {
        "genesis": self.genesis,
        "manifest": dict(self.manifest.value),
        "credentials": self.credentials,
        "incarnations": self.incarnations,
        "origin": self.origins["legion"],
    }
    (source / "public-authority.json").write_bytes(canonical_bytes(public))
    content = {}
    for digest, raw in self.contents.items():
        (source / (digest + ".txt")).write_bytes(raw)
        content[digest] = {"source_id": "context-002", "path": digest + ".txt"}
    learning = self.root_path / "selected-learning"
    learning.mkdir(mode=0o700)
    preservation.git_command(learning, "init", "-q")
    for text in (
        "Earlier attributed learned method.",
        "Current corrected learned method.",
    ):
        (learning / "lesson.md").write_text(text)
        preservation.git_command(learning, "add", "lesson.md")
        preservation.git_command(
            learning,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            text,
        )
    old_commit = preservation.git_command(learning, "rev-parse", "HEAD~1")
    roots = [("memory", self.hmk_base), ("context", source), ("context", learning)]
    selection = {
        "schema": preservation.SELECTION,
        "hmk": [{"source_id": "memory-001", "path": "library.db"}],
        "matrix": [{"source_id": "context-002", "path": "ledger.sqlite"}],
        "content": content,
        "artifacts": [
            {
                "source_id": "context-003",
                "path": "lesson.md",
                "role": "native-learned-artifact",
            }
        ],
        "git_sources": ["context-003"],
        "world_references": ["https://example.invalid/project/issues/47"],
        "implementation_qualification": {
            "wire_contract_hmk_commit": HMK_COMMIT,
            "tested_hmk_commit": CURRENT_HMK_COMMIT,
        },
        "unknown_future_field": {"preserve": [1, "original"]},
    }
    profile_dir = self.root_path / "profile"
    preservation.build(
        archive.discover("Fixture", roots),
        selection,
        profile_dir,
        writers_stopped=True,
    )
    roots.append(("context", profile_dir))
    packet = self.root_path / "source-packet.tgz"
    archive.export(archive.discover("Fixture", roots), packet, writers_stopped=True)
    checksum = archive.digest(packet)
    transported = self.root_path / "transported.tgz"
    shutil.copyfile(packet, transported)
    self.assertEqual(archive.digest(transported), checksum)
    for _, path in roots:
        shutil.rmtree(path)
    shutil.rmtree(self.root_path / "legion")
    self.contents.clear()
    stage = self.root_path / "received"
    archive.verify(transported, expected_sha256=checksum, destination=stage)
    profile_member = "payload/context-004/memory-preservation.json"
    proof = preservation.verify(stage, profile_member)
    self.assertTrue(proof["complete_available_content"])
    received_db = stage / "payload/memory-001/library.db"
    self.assertEqual(preservation.database_state(received_db), original_state)
    profile = json.loads((stage / profile_member).read_bytes())
    self.assertEqual(profile["selection"], selection)
    # Replay verification neither changes the receiver nor counts as admission.
    self.assertEqual(preservation.verify(stage, profile_member), proof)
    dependency = stage / profile["dependencies"][0]["member"]
    exact = dependency.read_bytes()
    dependency.unlink()
    with self.assertRaises(preservation.PreservationError):
        preservation.verify(stage, profile_member)
    dependency.write_bytes(b"Altered statement")
    with self.assertRaises(preservation.PreservationError):
        preservation.verify(stage, profile_member)
    dependency.write_bytes(exact)
    self.assertEqual(preservation.verify(stage, profile_member), proof)
    bare = self.root_path / "restored-learning.git"
    preservation.git_command(
        self.root_path,
        "clone",
        "--bare",
        str(stage / profile["git_history"][0]["bundle"]),
        str(bare),
    )
    self.assertEqual(
        preservation.git_command(bare, "show", old_commit + ":lesson.md"),
        "Earlier attributed learned method.",
    )
    authority_doc = json.loads(
        (stage / "payload/context-002/public-authority.json").read_bytes()
    )
    authority = RootAuthority(
        BeingManifest.from_value(authority_doc["manifest"]),
        verify_genesis(authority_doc["genesis"]),
        authority_doc["credentials"],
        authority_doc["incarnations"],
    )
    ledger = Ledger(
        stage / "payload/context-002/ledger.sqlite",
        authority=authority,
        local_origin=authority_doc["origin"],
        clock=lambda: NOW,
    )
    ledger.integrity_check()
    page = ledger.known_page(cursor=None, limit=64)
    for event in page["events"]:
        verify_event(event, authority)
    self.assertEqual(
        [e["event_id"] for e in page["events"]],
        [
            asserted["event_id"],
            corrected["event_id"],
            doomed["event_id"],
            retracted["event_id"],
            active["event_id"],
        ],
    )
    target = self.root_path / "clean-hmk"
    target.mkdir(mode=0o700)
    archive.copy_source(received_db, target / "library.db")
    transport = HMKCLITransport(self.hmk_root, target, instance="hmk:synthetic")
    adapter = MemoryProjectionAdapter(
        ledger=ledger,
        profile=create_projection_profile(
            source_instance="matrix:embodiment:legion",
            target_instance="hmk:synthetic",
        ),
        transport=transport,
        content_resolver=lambda ref: (
            stage / "payload/context-002" / (ref["sha256"] + ".txt")
        ).read_bytes(),
        journal=ProjectionJournal(self.root_path / "clean-journal/journal.sqlite"),
    )
    with self.assertRaisesRegex(
        MemoryProjectionError, "memory_projection_event_not_current"
    ):
        adapter.project(
            event_id=asserted["event_id"], idempotency_key="portable:obsolete"
        )
    rebuild = adapter.rebuild_plan(
        request_id="34000000-0000-4000-8000-000000000098",
        idempotency_key="portable:rebuild",
    )
    rebuilt = adapter.rebuild_apply(rebuild)
    self.assertEqual(adapter.rebuild_apply(rebuild), rebuilt)
    adapter.verify()
    self.assertEqual(
        adapter.recall(memory_id=active_id)["statement"]["text"],
        "A previous body learned a sensor skill; this body has no sensor.",
    )
    with self.assertRaises(MemoryProjectionError):
        adapter.recall(memory_id=retracted_id)
    self.assertEqual(
        adapter.recall(memory_id=MEMORY_ID)["statement"]["text"],
        "Two recovered; the third remained lost.",
    )
    with closing(sqlite3.connect(transport.database)) as db:
        for name, rows in native.items():
            after = db.execute("SELECT * FROM " + name).fetchall()
            self.assertTrue(all(row in after for row in rows), name)
    lookup_cases = []
    if corpus:
        cases = (
            ("1847", "HarborMesh issue 47", "Mara Ibarra"),
            (
                "invite-81",
                "inviting Jo Vale to a mount-comparison workshop",
                "Delivery failed",
            ),
            (
                "chart-52",
                "passing our annotated chart to Ren",
                "recipient link was not published",
            ),
            ("third node", "April 30 HarborMesh trial", "third node lost"),
        )
        for query, title, support in cases:
            results = transport.memoryctl("search", "--query", query, "--limit", "8")
            found = [r for r in results if r["title"] == title]
            self.assertTrue(found, title)
            self.assertIn(support, found[0]["raw"])
            lookup_cases.append({"query": query, "title": title, "supported": True})
    report = {
        "bounded_native_lookup": lookup_cases,
        "schema": "hmk.stage-three-qualification/v1",
        "hmk_commit": CURRENT_HMK_COMMIT,
        "wire_contract_hmk_commit": HMK_COMMIT,
        "archive_sha256": checksum,
        "archive_bytes": transported.stat().st_size,
        "staged_bytes": sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()),
        "original_chapters": len(native["chapters"]),
        "original_revisions": len(native["chapter_revisions"]),
        "original_database_state": original_state,
        "matrix_signed_events": len(page["events"]),
        "preservation": proof,
        "source_free_restore": True,
        "missing_and_altered_dependency_detected": True,
        "git_prior_revision_restored": True,
        "replay_and_rebuild": True,
        "elapsed_milliseconds": round((time.monotonic() - started) * 1000),
        "sqlite_rollback_verified": True,
        "implementation_script_hashes": {
            name: hashlib.sha256(
                (self.hmk_root / "scripts" / name).read_bytes()
            ).hexdigest()
            for name in ("daimon_projection.py", "memoryctl.py")
        },
        "model_calls": 0,
        "embedding_calls": 0,
        "api_cost_usd": 0,
    }
    rollback = self.root_path / "rollback"
    rollback.mkdir(mode=0o700)
    archive.copy_source(received_db, rollback / "library.db")
    self.assertEqual(
        preservation.database_state(rollback / "library.db"), original_state
    )
    evidence = os.environ.get("HMK_PRESERVATION_EVIDENCE")
    if evidence:
        evidence_dir = Path(evidence)
        evidence_dir.mkdir(mode=0o700)
        shutil.copyfile(transported, evidence_dir / "portable-fixture.tgz")
        shutil.copyfile(
            stage / profile_member, evidence_dir / "memory-preservation.json"
        )
    output = os.environ.get("HMK_PRESERVATION_REPORT")
    if output:
        Path(output).write_bytes(canonical_bytes(report))
