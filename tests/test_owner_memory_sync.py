from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from daimon_matrix.owner_memory_sync import (
    compare_pools,
    main,
    projection_states,
    publish_private_packet,
    read_private_packet,
    rebuild_projection_packet,
)


class OwnerMemoryComparisonTests(unittest.TestCase):
    def test_native_cli_refuses_tampered_packet_before_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet = root / "native.json"
            packet.write_text('{"private": "synthetic-private-statement"}')
            packet.chmod(0o600)
            output = io.StringIO()
            with (
                contextlib.redirect_stdout(output),
                patch("daimon_matrix.owner_memory_sync.subprocess.run") as worker,
            ):
                code = main(
                    [
                        "apply-native",
                        "--packet",
                        str(packet),
                        "--sha256",
                        "0" * 64,
                        "--binding",
                        str(root / "missing-binding.json"),
                        "--binding-sha256",
                        "0" * 64,
                        "--state",
                        str(root / "state.json"),
                        "--native-root",
                        str(root / "absent-native"),
                        "--python",
                        "/absent-python",
                        "--isolated-home",
                        str(root),
                    ]
                )
            self.assertEqual(code, 1)
            worker.assert_not_called()
            self.assertEqual(
                json.loads(output.getvalue()),
                {
                    "ok": False,
                    "code": "owner_native_sync_apply_failed",
                },
            )
            self.assertFalse((root / "state.json").exists())

    def test_rebuild_selection_mismatch_and_occupied_output_precede_journals(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "native.py"
            script.write_text("# synthetic I/O seam\n")
            selection = root / "selection.json"
            pin = publish_private_packet(
                selection,
                {
                    "target_pool_proposal": str(root),
                    "target_instance": "synthetic",
                    "entries": [{"event_id": "selected-head"}],
                },
            )
            saved = root / "saved.json"
            saved_pin = publish_private_packet(
                saved,
                {
                    "entries": [{"event_id": "different-head"}],
                },
            )
            before = saved.read_bytes()
            arguments = dict(
                packet=selection,
                sha256=pin,
                profile_root=root,
                content_root=root,
                native_root=root,
                python=Path("/synthetic-python"),
                isolated_home=root,
                saved=saved,
            )
            with (
                patch(
                    "daimon_matrix.owner_memory_sync.check_native_checkout",
                    return_value=script,
                ),
                patch(
                    "daimon_matrix.owner_memory_sync.bound_projection_runtime",
                    return_value=contextlib.nullcontext((None, root / "library.db")),
                ),
                patch("daimon_matrix.owner_memory_sync.load_saved_rebuilds") as load,
                patch("daimon_matrix.owner_memory_sync.prepare_rebuilds") as prepare,
            ):
                with self.assertRaisesRegex(ValueError, "selection_mismatch"):
                    rebuild_projection_packet(**arguments, saved_sha256=saved_pin)
                with self.assertRaises(FileExistsError):
                    rebuild_projection_packet(**arguments, saved_sha256=None)
            load.assert_not_called()
            prepare.assert_not_called()
            self.assertEqual(saved.read_bytes(), before)

    def test_projection_cli_refuses_packet_tamper_before_native_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packet = root / "selected.json"
            packet.write_text('{"private": "synthetic-private-statement"}')
            packet.chmod(0o600)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "project-selected",
                        "--packet",
                        str(packet),
                        "--sha256",
                        "0" * 64,
                        "--profile-root",
                        str(root),
                        "--content-root",
                        str(root),
                        "--native-root",
                        str(root / "absent-native"),
                        "--python",
                        "/absent-python",
                        "--isolated-home",
                        str(root),
                        "--initial-pool-sha256",
                        "0" * 64,
                    ]
                )
            self.assertEqual(code, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"ok": False, "code": "owner_selected_projection_failed"},
            )
            self.assertNotIn("synthetic-private-statement", output.getvalue())
            self.assertFalse((root / "absent-native").exists())

    def test_private_packet_fifo_refuses_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "packet.json"
            os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(ValueError, "runtime_file_not_owner_only"):
                read_private_packet(path, "0" * 64)

    def test_projection_heads_and_origin_are_visible_as_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = [Path(temporary) / name for name in ("left.db", "right.db")]
            for index, path in enumerate(paths):
                with contextlib.closing(sqlite3.connect(path)) as connection:
                    connection.executescript("""
                        CREATE TABLE daimon_projection_namespaces (
                            namespace_id TEXT, source_instance TEXT, subject_me_id TEXT,
                            projector_id TEXT, projector_version TEXT);
                        CREATE TABLE daimon_projections (
                            namespace_id TEXT, memory_id TEXT, author_me_id TEXT,
                            category TEXT, classification TEXT, head_event_id TEXT,
                            head_event_hash TEXT, statement_hash TEXT,
                            statement_length INTEGER,
                            statement_media_type TEXT, active INTEGER,
                            chapter_id INTEGER);
                    """)
                    connection.execute(
                        "INSERT INTO daimon_projection_namespaces VALUES (?,?,?,?,?)",
                        (
                            "namespace",
                            "synthetic-origin",
                            "synthetic-being",
                            "hmk",
                            "1",
                        ),
                    )
                    connection.execute(
                        "INSERT INTO daimon_projections VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            "namespace",
                            "memory",
                            "synthetic-being",
                            "experience",
                            "personal",
                            "head",
                            "hash",
                            "content-hash",
                            42,
                            "text/plain",
                            1,
                            index,
                        ),
                    )
                    connection.commit()
            self.assertEqual(projection_states(paths[0]), projection_states(paths[1]))
            with contextlib.closing(sqlite3.connect(paths[1])) as connection:
                connection.execute(
                    "UPDATE daimon_projections SET head_event_hash='changed-head'"
                )
                connection.commit()
            self.assertNotEqual(
                projection_states(paths[0]), projection_states(paths[1])
            )
            with contextlib.closing(sqlite3.connect(paths[1])) as connection:
                connection.execute(
                    "UPDATE daimon_projections SET head_event_hash='hash'"
                )
                connection.execute(
                    "UPDATE daimon_projection_namespaces SET "
                    "source_instance='substituted-origin'"
                )
                connection.commit()
            self.assertNotEqual(
                projection_states(paths[0]), projection_states(paths[1])
            )

    def test_private_packet_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            document = {"schema": "synthetic", "private": "synthetic-private-marker"}
            pin = publish_private_packet(path, document)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pin)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                publish_private_packet(path, {"different": True})
            self.assertEqual(path.read_bytes(), before)

    def test_read_only_content_free_comparison_and_duplicate_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            left, right = (Path(temporary) / name for name in ("left.db", "right.db"))
            for path in (left, right):
                with contextlib.closing(sqlite3.connect(path)) as connection:
                    for table in (
                        "shelves",
                        "books",
                        "chapters",
                        "chapter_links",
                        "queries_log",
                        "chapter_embeddings",
                        "link_suggestions",
                    ):
                        connection.execute(f"CREATE TABLE {table} (value BLOB)")
                    connection.execute(
                        "INSERT INTO chapters VALUES (?)",
                        (b"synthetic-private-memory-marker",),
                    )
                    connection.commit()
            before = hashlib.sha256(left.read_bytes()).hexdigest()
            equal = compare_pools(left, right)
            self.assertTrue(equal["equal_native_tables"])
            self.assertNotIn("synthetic-private-memory-marker", json.dumps(equal))
            with contextlib.closing(sqlite3.connect(right)) as connection:
                connection.execute(
                    "INSERT INTO chapters VALUES (?)",
                    (b"synthetic-private-memory-marker",),
                )
                connection.commit()
            different = compare_pools(left, right)
            self.assertFalse(different["equal_native_tables"])
            self.assertEqual(different["tables"]["chapters"]["left_rows"], 1)
            self.assertEqual(different["tables"]["chapters"]["right_rows"], 2)
            self.assertFalse(different["authority_verified"])
            self.assertFalse(different["writer_cutoff_verified"])
            self.assertEqual(hashlib.sha256(left.read_bytes()).hexdigest(), before)

    def test_missing_pool_is_not_created_and_diagnostic_is_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-private-name.db"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(
                    ["drift", "--left", str(missing), "--right", str(missing)]
                )
            self.assertEqual(result, 1)
            self.assertEqual(
                json.loads(output.getvalue()),
                {"ok": False, "code": "owner_memory_pool_comparison_failed"},
            )
            self.assertFalse(missing.exists())
