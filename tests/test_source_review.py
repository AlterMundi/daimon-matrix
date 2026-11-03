"""Operator review bounds and truthful offered/received distinctions."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import time
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "source_review", Path(__file__).parents[1] / "tools/source_review.py"
)
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
SELECTOR = {"source_id": "dm:source:v0:" + "a" * 43, "source_core_hash": "a" * 43}


def server(name):
    return {
        key: name + key
        for key in ("body_ref", "embodiment_id", "incarnation_id", "principal_id")
    }


def observed(name, publications=(), active=False):
    return {
        "server": server(name),
        "native_calls": 1 + len(publications),
        "sources": [
            {
                "status": {
                    "observer_me_id": name,
                    "selector": SELECTOR,
                    "claims": [],
                    "publications": list(publications),
                },
                "projections": {
                    p["publication_id"]: {
                        "active": active,
                        "publication_event_hash": p["event_hash"],
                    }
                    for p in publications
                },
            }
        ],
    }


def publication():
    return {
        "publication_id": "pub",
        "publisher_me_id": "author",
        "event_hash": "h1",
        "sequence": 0,
        "state": "published",
    }


class SourceReviewTests(unittest.TestCase):
    def test_calendar_is_finite_before_expiry_and_local_index_is_not_live_discovery(
        self,
    ):
        settings = self.settings()
        settings["max_runs"] = 128
        settings["expires_at_ms"] = 180001
        slots = review.calendar_slots(settings, 1)
        self.assertEqual(len(slots), 2)
        local = observed("receiver", [publication()])
        candidates = review.local_candidates({"receiver": local})
        self.assertEqual(candidates[0]["state"], "known-not-applied")
        self.assertEqual(
            candidates[0]["publisher_freshness"], "not-established-by-local-index"
        )
        self.assertEqual(review.compare({"receiver": local}), [])

    def test_native_not_promoted_is_not_a_transport_or_authority_failure(self):
        self.assertFalse(
            review.projection_flags(
                {
                    "ok": False,
                    "error": {
                        "code": "source_projection_not_promoted",
                        "retryable": False,
                    },
                }
            )["active"]
        )
        with self.assertRaisesRegex(ValueError, "projection_unavailable"):
            review.projection_flags(
                {"ok": False, "error": {"code": "permission_denied"}}
            )

    def settings(self):
        return {
            "schema": "dm.source-review-config/v1",
            "human_task": "fixture",
            "expires_at_ms": 1000000,
            "max_runs": 2,
            "interval_seconds": 60,
            "selectors": [SELECTOR],
            "targets": [
                {
                    "id": "author",
                    "being_ref": "author",
                    "server": server("author"),
                    "command": ["fixture"],
                }
            ],
        }

    def test_does_not_confuse_known_publications_with_owned_offers(self):
        pub = publication()
        values = {
            "author": observed("author", [pub]),
            "received": observed("received", [pub], active=True),
            "missing": observed("missing"),
            "offline": {"state": "unavailable"},
        }
        rows = review.compare(values)
        self.assertEqual(
            {x["receiver"]: x["state"] for x in rows},
            {
                "received": "already-applied",
                "missing": "offered",
                "offline": "unavailable",
            },
        )
        self.assertTrue(all(x["publisher"] == "author" for x in rows))
        values["received"]["sources"][0]["status"]["publications"][0] = {
            **pub,
            "event_hash": "different",
            "sequence": 0,
        }
        self.assertIn("conflicted", [x["state"] for x in review.compare(values)])

    def test_restart_pause_stop_and_limit_never_replenish_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, report = root / "state.json", root / "report.json"
            settings = self.settings()
            calls = []

            def call(*args):
                calls.append(args)
                return observed("author")

            def run(now, **kwargs):
                return review.review(
                    settings, state, report, call=call, now_ms=now, **kwargs
                )

            self.assertTrue(run(1)["changed"])
            self.assertEqual(run(2)["state"], "not-due")
            self.assertEqual(run(60001, control="pause")["native_calls"], 0)
            self.assertEqual(run(60001)["state"], "paused")
            self.assertEqual(run(60001, control="resume")["runs"], 1)
            self.assertFalse(run(60001)["changed"])
            self.assertEqual(run(120001)["state"], "finished")
            self.assertEqual(len(calls), 2)
            run(120001, control="resume")
            self.assertEqual(run(120001)["state"], "finished")
            settings["max_runs"] = 3
            with self.assertRaisesRegex(ValueError, "config_changed"):
                run(120001)

    def test_failure_and_wrong_identity_remain_unavailable_and_spend_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = review.review(
                self.settings(),
                root / "s.json",
                root / "r.json",
                call=lambda *_: observed("wrong-body"),
                now_ms=1,
            )
            self.assertEqual(result["unavailable"], ["author"])
            state = review.private_read(root / "s.json")
            self.assertEqual(state["runs"], 1)
            self.assertEqual(result["model_calls"], 0)
            self.assertFalse(result["automatic_adoption"])

    def test_expiration_and_stop_prevent_all_io(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            args = (self.settings(), root / "s.json", root / "r.json")
            self.assertEqual(
                review.review(*args, call=lambda *x: calls.append(x), now_ms=1000000)[
                    "state"
                ],
                "finished",
            )
            review.review(*args, control="stop", now_ms=1)
            review.review(*args, control="resume", now_ms=1)
            self.assertEqual(
                review.review(*args, call=lambda *x: calls.append(x), now_ms=1)[
                    "state"
                ],
                "finished",
            )
            self.assertEqual(calls, [])

    def test_output_and_descendant_lifetime_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "capacity"):
            review.bounded_call(
                [sys.executable, "-c", "import sys;sys.stdin.read();print('x'*300000)"],
                {},
                timeout=2,
            )
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "pid"
            command = (
                "import os,time,pathlib;child=os.fork();"
                "pathlib.Path('"
                + str(pidfile)
                + "').write_text(str(child)) if child else None;"
                "os._exit(0) if child else time.sleep(30)"
            )
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                review.bounded_call([sys.executable, "-c", command], {}, timeout=0.3)
            self.assertLess(time.monotonic() - started, 2)
            pid = int(pidfile.read_text())
            status = Path(f"/proc/{pid}/stat")
            deadline = time.monotonic() + 1
            while status.exists() and time.monotonic() < deadline:
                if status.read_text().split(")", 1)[1].split()[0] in {"Z", "X"}:
                    break
                time.sleep(0.01)
            if status.exists():
                self.assertIn(
                    status.read_text().split(")", 1)[1].split()[0], {"Z", "X"}
                )

    def test_incomplete_staging_is_reclaimed_and_report_cannot_replace_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / ".state.json.new"
            staged.write_bytes(b"incomplete")
            staged.chmod(0o600)
            review.write(root / "state.json", {"done": True})
            self.assertFalse(staged.exists())
            self.assertEqual(review.private_read(root / "state.json"), {"done": True})
            for output in [root / "state.json", root / "state.lock"]:
                with self.assertRaisesRegex(ValueError, "distinct"):
                    review.review(
                        self.settings(), root / "state.json", output, now_ms=1
                    )


if __name__ == "__main__":
    unittest.main()
