"""Durability and lifetime requirements for private upgrade copies."""

from __future__ import annotations

import os
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from daimon_matrix import operator_runtime_upgrade as upgrade


class UpgradeCopyTests(unittest.TestCase):
    def test_complete_tree_is_private_and_durable_before_return(self):
        snapshot = {
            "a": b"first",
            "nested/": b"",
            "nested/b": b"second",
            "nested/c": b"third",
            "empty/": b"",
        }
        events = []
        fsync = os.fsync

        def observed(fd):
            info = os.fstat(fd)
            events.append((stat.S_ISDIR(info.st_mode), info.st_ino))
            fsync(fd)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "copy"
            with patch.object(upgrade.os, "fsync", side_effect=observed):
                upgrade._copy(snapshot, target)
            self.assertEqual(upgrade._snapshot(target), snapshot)
            files = [p for p in target.rglob("*") if p.is_file()]
            self.assertEqual(
                {inode for is_dir, inode in events if not is_dir},
                {p.stat().st_ino for p in files},
            )
            synced_dirs = [inode for is_dir, inode in events if is_dir]
            self.assertEqual(len(synced_dirs), len(set(synced_dirs)))
            self.assertEqual(
                synced_dirs[-2:], [target.stat().st_ino, target.parent.stat().st_ino]
            )
            first_directory = next(i for i, event in enumerate(events) if event[0])
            self.assertTrue(all(event[0] for event in events[first_directory:]))
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in files))
            self.assertEqual(stat.S_IMODE((target / "empty").stat().st_mode), 0o700)

    def test_both_copies_run_concurrently_and_keep_exact_bytes(self):
        barrier = threading.Barrier(2)
        copy = upgrade._copy

        def overlapping(snapshot, destination):
            barrier.wait(timeout=5)
            copy(snapshot, destination)

        with tempfile.TemporaryDirectory() as directory:
            transaction = Path(directory)
            snapshot = {"retained": b"unchanged history"}
            with patch.object(upgrade, "_copy", side_effect=overlapping):
                result = upgrade._copy_capability_trees(snapshot, transaction)
            self.assertEqual(result, transaction / "successor")
            self.assertEqual(upgrade._snapshot(result), snapshot)
            self.assertEqual(upgrade._snapshot(transaction / "checkpoint"), snapshot)

    def test_copy_failure_waits_for_the_other_worker_before_return(self):
        barrier = threading.Barrier(2)
        copying = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        copy = upgrade._copy

        def interrupted(snapshot, destination):
            barrier.wait(timeout=5)
            if destination.name == "checkpoint":
                raise OSError("synthetic copy failure")
            copying.set()
            self.assertTrue(release.wait(timeout=5))
            copy(snapshot, destination)
            finished.set()

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(upgrade, "_copy", side_effect=interrupted),
            ThreadPoolExecutor(max_workers=1) as caller,
        ):
            future = caller.submit(
                upgrade._copy_capability_trees,
                {"history": b"retained"},
                Path(directory),
            )
            self.assertTrue(copying.wait(timeout=5))
            self.assertFalse(future.done())
            release.set()
            with self.assertRaisesRegex(OSError, "synthetic copy failure"):
                future.result(timeout=5)
        self.assertTrue(finished.is_set())


if __name__ == "__main__":
    unittest.main()
