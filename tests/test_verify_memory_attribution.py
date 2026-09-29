"""The attribution verifier, including the substitution it exists to catch.

The fixtures are built directly rather than through the memory policy machinery,
because what is under test is the cross-document checking: a pool row, a signed
event, and whether the two agree. Constructing both sides makes disagreement
expressible, which is the whole point.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.verify_memory_attribution import REPORT_SCHEMA, main, verify

BEING = "dm:being:v1:" + "B" * 43
EMBODIMENT_A = "embodiment:11111111-1111-4111-8111-111111111111"
EMBODIMENT_B = "embodiment:22222222-2222-4222-8222-222222222222"
INSTANCE_A = f"matrix:{EMBODIMENT_A}"
INSTANCE_B = f"matrix:{EMBODIMENT_B}"
STATEMENT = b"one lived experience, stated once"
STATEMENT_SHA = hashlib.sha256(STATEMENT).hexdigest()


def _event(
    embodiment_id: str, event_id: str, *, memory_id: str = "mem-1"
) -> tuple[str, str]:
    """One signed-shaped event and its content hash."""

    payload = {
        "author_me_id": BEING,
        "category": "personal-insight",
        "memory_id": memory_id,
        "content_ref": {
            "schema": "dm.memory.content-ref/v1",
            "content_id": "dm:memory-content:v1:x",
            "sha256": STATEMENT_SHA,
            "byte_length": len(STATEMENT),
            "media_type": "text/plain",
            "classification": "personal",
        },
    }
    body = {
        "event_id": event_id,
        "kind": "memory.recorded",
        "being_ref": BEING,
        "origin": {
            "body_ref": "cli:test:compaii",
            "embodiment_id": embodiment_id,
            "incarnation_id": "incarnation:test:0",
            "principal_id": "compaii.test@host",
        },
        "payload": payload,
        "sequence": 1,
    }
    raw = json.dumps(body, sort_keys=True)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


class AttributionFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pool = self.root / "library.db"
        self.pool_calls = 0

    def body(
        self, name: str, embodiment_id: str, events: dict[str, tuple[str, str]]
    ) -> Path:
        runtime = self.root / name
        runtime.mkdir(mode=0o700)
        (runtime / "runtime.json").write_bytes(
            json.dumps(
                {
                    "schema": "dm.runtime.bundle/v7",
                    "local_origin": {
                        "body_ref": "cli:test:compaii",
                        "embodiment_id": embodiment_id,
                        "incarnation_id": "incarnation:test:0",
                        "principal_id": "compaii.test@host",
                    },
                }
            ).encode()
        )
        ledger = sqlite3.connect(runtime / "ledger.sqlite")
        try:
            ledger.execute(
                "CREATE TABLE events (event_id TEXT PRIMARY KEY, event_json TEXT, "
                "content_hash TEXT)"
            )
            for event_id, (raw, digest) in events.items():
                ledger.execute(
                    "INSERT INTO events VALUES (?, ?, ?)", (event_id, raw, digest)
                )
            ledger.commit()
        finally:
            ledger.close()
        return runtime

    def pool_with(
        self,
        *,
        namespaces: list[dict[str, Any]],
        projections: list[dict[str, Any]],
        chapters: int = 3,
    ) -> Path:
        # One file per call: a pool is a whole database, and reusing the path would
        # make a second call collide on CREATE TABLE instead of building a fresh pool.
        self.pool_calls += 1
        pool = self.root / f"library-{self.pool_calls}.db"
        database = sqlite3.connect(pool)
        try:
            database.execute(
                "CREATE TABLE daimon_projection_namespaces ("
                "namespace_id TEXT PRIMARY KEY, "
                "source_instance TEXT, subject_me_id TEXT, projector_id TEXT, "
                "projector_version TEXT, generation TEXT, "
                "accepted_checkpoint_sequence TEXT)"
            )
            database.execute(
                "CREATE TABLE daimon_projections (projection_id TEXT PRIMARY KEY, "
                "namespace_id TEXT, memory_id TEXT, chapter_id INTEGER, "
                "active INTEGER, "
                "category TEXT, head_event_id TEXT, head_event_hash TEXT, "
                "statement_hash TEXT, statement_length INTEGER, "
                "statement_media_type TEXT, classification TEXT, author_me_id TEXT)"
            )
            database.execute(
                "CREATE TABLE chapters (id INTEGER PRIMARY KEY, title TEXT)"
            )
            for row in namespaces:
                database.execute(
                    "INSERT INTO daimon_projection_namespaces VALUES "
                    "(:namespace_id, :source_instance, :subject_me_id, :projector_id, "
                    ":projector_version, :generation, :accepted_checkpoint_sequence)",
                    {
                        "projector_id": "matrix:personal-memory-projector",
                        "projector_version": "1.0.0",
                        "generation": "1",
                        "accepted_checkpoint_sequence": "1",
                        **row,
                    },
                )
            for row in projections:
                database.execute(
                    "INSERT INTO daimon_projections VALUES "
                    "(:projection_id, :namespace_id, "
                    ":memory_id, :chapter_id, :active, :category, :head_event_id, "
                    ":head_event_hash, :statement_hash, :statement_length, "
                    ":statement_media_type, :classification, :author_me_id)",
                    {
                        "active": 1,
                        "category": "personal-insight",
                        "statement_hash": STATEMENT_SHA,
                        "statement_length": len(STATEMENT),
                        "statement_media_type": "text/plain",
                        "classification": "personal",
                        "author_me_id": BEING,
                        **row,
                    },
                )
            for index in range(chapters):
                database.execute(
                    "INSERT INTO chapters VALUES (?, ?)",
                    (index + 1, f"chapter {index}"),
                )
            database.commit()
        finally:
            database.close()
        return pool


class VerifyAttributionTests(AttributionFixture):
    def attributed_pair(self) -> tuple[Path, list[Path]]:
        """Two embodiments of one being, one shared pool, one attributed row each."""

        event_a = _event(EMBODIMENT_A, "event-a")
        event_b = _event(EMBODIMENT_B, "event-b", memory_id="mem-2")
        runtime_a = self.body("body-a", EMBODIMENT_A, {"event-a": event_a})
        runtime_b = self.body("body-b", EMBODIMENT_B, {"event-b": event_b})
        pool = self.pool_with(
            namespaces=[
                {
                    "namespace_id": "ns-a",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                },
                {
                    "namespace_id": "ns-b",
                    "source_instance": INSTANCE_B,
                    "subject_me_id": BEING,
                },
            ],
            projections=[
                {
                    "projection_id": "proj-a",
                    "namespace_id": "ns-a",
                    "memory_id": "mem-1",
                    "chapter_id": 1,
                    "head_event_id": "event-a",
                    "head_event_hash": event_a[1],
                },
                {
                    "projection_id": "proj-b",
                    "namespace_id": "ns-b",
                    "memory_id": "mem-2",
                    "chapter_id": 2,
                    "head_event_id": "event-b",
                    "head_event_hash": event_b[1],
                },
            ],
            chapters=5,
        )
        return pool, [runtime_a, runtime_b]

    def test_two_embodiments_of_one_being_are_distinguishable_in_one_pool(self) -> None:
        pool, runtimes = self.attributed_pair()
        report = verify(pool, runtimes)
        self.assertEqual(report["schema"], REPORT_SCHEMA)
        self.assertTrue(report["verified"], report["reasons"])
        self.assertEqual(report["reasons"], [])
        # Attribution is a JOIN over namespaces, one per embodiment, both under the
        # same being: shared surface, distinguishable authorship, no partition.
        self.assertEqual(len(report["namespaces"]), 2)
        self.assertEqual(
            {row["subject_me_id"] for row in report["namespaces"]}, {BEING}
        )
        self.assertEqual(
            sorted(str(row["source_instance"]) for row in report["namespaces"]),
            sorted([INSTANCE_A, INSTANCE_B]),
        )
        self.assertEqual(
            sorted(row["state"] for row in report["projections"]),
            ["verified", "verified"],
        )
        for row in report["projections"]:
            self.assertTrue(all(row["checks"].values()), row)
        # Direct unsigned writes coexist and are counted, never silently folded in.
        self.assertEqual(report["chapters_total"], 5)
        self.assertEqual(report["chapters_attributed"], 2)
        self.assertEqual(report["chapters_unattributed"], 3)
        self.assertEqual(
            main(["--pool", str(pool), *[f"--runtime={r}" for r in runtimes]]), 0
        )

    def test_a_row_claiming_another_embodiment_than_its_signer_is_caught(self) -> None:
        """The substitution the whole design exists to prevent."""

        # The event was signed by embodiment B, but the namespace claims A.
        event = _event(EMBODIMENT_B, "event-a")
        runtime_a = self.body("body-a", EMBODIMENT_A, {"event-a": event})
        pool = self.pool_with(
            namespaces=[
                {
                    "namespace_id": "ns-a",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                }
            ],
            projections=[
                {
                    "projection_id": "proj-a",
                    "namespace_id": "ns-a",
                    "memory_id": "mem-1",
                    "chapter_id": 1,
                    "head_event_id": "event-a",
                    "head_event_hash": event[1],
                }
            ],
        )
        report = verify(pool, [runtime_a])
        self.assertFalse(report["verified"])
        row = report["projections"][0]
        self.assertEqual(row["state"], "unverified")
        self.assertFalse(row["checks"]["origin_embodiment_matches_namespace"])
        # Every other field still matches, so the failure is precisely the claim of
        # authorship and not incidental drift.
        self.assertTrue(row["checks"]["head_event_hash"])
        self.assertTrue(row["checks"]["statement_hash"])
        self.assertTrue(
            any("origin_embodiment_matches_namespace" in r for r in report["reasons"])
        )
        self.assertEqual(main(["--pool", str(pool), f"--runtime={runtime_a}"]), 1)

    def test_a_tampered_statement_or_head_hash_is_caught(self) -> None:
        event = _event(EMBODIMENT_A, "event-a")
        runtime = self.body("body-a", EMBODIMENT_A, {"event-a": event})
        for field, value, expected_check in (
            ("statement_hash", "0" * 64, "statement_hash"),
            ("head_event_hash", "0" * 64, "head_event_hash"),
            ("statement_length", len(STATEMENT) + 1, "statement_length"),
            ("classification", "public", "classification"),
            ("category", "world-fact", "category"),
        ):
            with self.subTest(field=field):
                pool = self.pool_with(
                    namespaces=[
                        {
                            "namespace_id": "ns-a",
                            "source_instance": INSTANCE_A,
                            "subject_me_id": BEING,
                        }
                    ],
                    projections=[
                        {
                            "projection_id": "proj-a",
                            "namespace_id": "ns-a",
                            "memory_id": "mem-1",
                            "chapter_id": 1,
                            "head_event_id": "event-a",
                            "head_event_hash": event[1],
                            field: value,
                        }
                    ],
                )
                report = verify(pool, [runtime])
                self.assertFalse(report["verified"], field)
                self.assertFalse(report["projections"][0]["checks"][expected_check])

    def test_a_head_event_absent_from_the_naming_ledger_is_a_failure(self) -> None:
        event = _event(EMBODIMENT_A, "event-a")
        runtime = self.body("body-a", EMBODIMENT_A, {})  # ledger without the event
        pool = self.pool_with(
            namespaces=[
                {
                    "namespace_id": "ns-a",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                }
            ],
            projections=[
                {
                    "projection_id": "proj-a",
                    "namespace_id": "ns-a",
                    "memory_id": "mem-1",
                    "chapter_id": 1,
                    "head_event_id": "event-a",
                    "head_event_hash": event[1],
                }
            ],
        )
        report = verify(pool, [runtime])
        self.assertFalse(report["verified"])
        self.assertEqual(report["projections"][0]["state"], "unverified")
        self.assertTrue(any("head_event_absent" in r for r in report["reasons"]))

    def test_a_namespace_from_another_host_is_reported_not_failed(self) -> None:
        """One host cannot judge another's ledger, and must not pretend to."""

        event = _event(EMBODIMENT_A, "event-a")
        runtime = self.body("body-a", EMBODIMENT_A, {"event-a": event})
        pool = self.pool_with(
            namespaces=[
                {
                    "namespace_id": "ns-a",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                },
                {
                    "namespace_id": "ns-b",
                    "source_instance": INSTANCE_B,
                    "subject_me_id": BEING,
                },
            ],
            projections=[
                {
                    "projection_id": "proj-a",
                    "namespace_id": "ns-a",
                    "memory_id": "mem-1",
                    "chapter_id": 1,
                    "head_event_id": "event-a",
                    "head_event_hash": event[1],
                },
                {
                    "projection_id": "proj-b",
                    "namespace_id": "ns-b",
                    "memory_id": "mem-2",
                    "chapter_id": 2,
                    "head_event_id": "event-b",
                    "head_event_hash": "f" * 64,
                },
            ],
        )
        report = verify(pool, [runtime])
        self.assertTrue(report["verified"], report["reasons"])
        states = {row["projection_id"]: row["state"] for row in report["projections"]}
        self.assertEqual(states["proj-a"], "verified")
        self.assertEqual(states["proj-b"], "remote")
        remote = next(
            r for r in report["projections"] if r["projection_id"] == "proj-b"
        )
        self.assertEqual(remote["checks"], {})
        self.assertEqual(
            [
                n["verifiable_from_here"]
                for n in sorted(
                    report["namespaces"], key=lambda r: str(r["namespace_id"])
                )
            ],
            [True, False],
        )
        self.assertEqual(main(["--pool", str(pool), f"--runtime={runtime}"]), 0)

    def test_two_namespaces_claiming_one_embodiment_is_a_defect(self) -> None:
        event = _event(EMBODIMENT_A, "event-a")
        runtime = self.body("body-a", EMBODIMENT_A, {"event-a": event})
        pool = self.pool_with(
            namespaces=[
                {
                    "namespace_id": "ns-a",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                },
                {
                    "namespace_id": "ns-a2",
                    "source_instance": INSTANCE_A,
                    "subject_me_id": BEING,
                },
            ],
            projections=[
                {
                    "projection_id": "proj-a",
                    "namespace_id": "ns-a",
                    "memory_id": "mem-1",
                    "chapter_id": 1,
                    "head_event_id": "event-a",
                    "head_event_hash": event[1],
                }
            ],
        )
        report = verify(pool, [runtime])
        self.assertFalse(report["verified"])
        self.assertTrue(
            any(
                "duplicate_namespace_for_source_instance" in r
                for r in report["reasons"]
            )
        )

    def test_an_orphaned_projection_is_a_defect(self) -> None:
        pool = self.pool_with(
            namespaces=[],
            projections=[
                {
                    "projection_id": "proj-x",
                    "namespace_id": "ns-missing",
                    "memory_id": "mem-9",
                    "chapter_id": 1,
                    "head_event_id": "event-x",
                    "head_event_hash": "0" * 64,
                }
            ],
        )
        report = verify(pool, [])
        self.assertFalse(report["verified"])
        self.assertEqual(report["projections"][0]["state"], "orphaned")

    def test_verification_never_writes_anything(self) -> None:
        pool, runtimes = self.attributed_pair()
        targets = [pool, *(runtime / "ledger.sqlite" for runtime in runtimes)]
        targets += [runtime / "runtime.json" for runtime in runtimes]
        before = {
            path: (path.read_bytes(), path.stat().st_mtime_ns) for path in targets
        }
        # Canaries that must never be opened, let alone read.
        for runtime in runtimes:
            for name in ("custody.json", "body.password", "client.key"):
                (runtime / name).write_bytes(b"canary")
                (runtime / name).chmod(0o600)
        canaries = {
            path: (runtime / name).read_bytes()
            for runtime in runtimes
            for name in ("custody.json", "body.password", "client.key")
            for path in [runtime / name]
        }
        report = verify(pool, runtimes)
        self.assertTrue(report["verified"], report["reasons"])
        after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in targets}
        self.assertEqual(before, after, "verification touched a database or bundle")
        self.assertEqual(
            canaries,
            {path: path.read_bytes() for path in canaries},
            "verification read custody material",
        )

    def test_a_missing_pool_is_reported_not_crashed(self) -> None:
        report = verify(self.root / "absent.db", [])
        self.assertFalse(report["verified"])
        self.assertEqual(report["reasons"], ["pool_missing"])
        self.assertEqual(main(["--pool", str(self.root / "absent.db")]), 1)


if __name__ == "__main__":
    unittest.main()
