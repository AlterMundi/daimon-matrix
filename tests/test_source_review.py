"""Operator review bounds and truthful offered/received distinctions."""

from __future__ import annotations

import copy
import fcntl
import importlib.util
import json
import os
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
ANCESTRY = {"source_id": "dm:source:v0:" + "b" * 43, "source_core_hash": "b" * 43}


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
    def report_fixture(self, path):
        value = {
            "schema": "dm.source-review/v2",
            "cursor": "current-cursor",
            "observed_at_ms": 123,
            "offers": [{"publication_id": "selected"}],
            "local_candidates": [],
            "unavailable": [],
            "ancestry": {"claims": ["admitted-descendant"]},
            "model_calls": 0,
            "automatic_adoption": False,
            "configuration": {"command": ["not-exported"]},
        }
        review.write(path, value)
        return path.read_bytes()

    def test_export_preserves_producer_and_selects_only_report_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "report.json", root / "reader.json"
            before = self.report_fixture(source)
            result = review.export_report(source, target)
            projected = review.private_read(target)
            self.assertEqual(projected["schema"], "dm.source-review-projection/v1")
            self.assertEqual(
                projected["metadata"]["offers"], [{"publication_id": "selected"}]
            )
            self.assertEqual(projected["source_cursor"], "current-cursor")
            self.assertNotIn("configuration", projected["metadata"])
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(target.stat().st_uid, os.geteuid())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result["native_calls"], 0)
            self.assertFalse(result["source_mutated"])
            review.export_report(source, target)
            self.assertEqual(
                len(list(root.glob("reader*"))), 2
            )  # latest plus fixed empty lock
            self.assertFalse((root / ".reader.json.new").exists())

    def test_export_invalid_source_and_lock_contention_retain_prior_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "report.json", root / "reader.json"
            original = self.report_fixture(source)
            review.export_report(source, target)
            before = target.read_bytes()
            with self.assertRaisesRegex(ValueError, "distinct"):
                review.export_report(source, source)
            source.write_bytes(b"invalid JSON")
            with self.assertRaises(json.JSONDecodeError):
                review.export_report(source, target)
            source.write_bytes(original)
            source.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private_owner"):
                review.export_report(source, target)
            source.chmod(0o600)
            lock = os.open(root / "reader.json.lock", os.O_RDWR)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    review.export_report(source, target)
            finally:
                os.close(lock)
            self.assertEqual(target.read_bytes(), before)
            self.assertEqual(source.read_bytes(), original)

    def test_export_rejects_config_capacity_and_invalid_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, target = root / "report.json", root / "reader.json"
            review.write(source, self.settings())
            with self.assertRaisesRegex(ValueError, "source_review_report"):
                review.export_report(source, target)
            source.write_bytes(b" " * (review.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "capacity"):
                review.export_report(source, target)
            source.unlink()  # Retire only this test's deliberately oversized fixture.
            self.report_fixture(source)
            with self.assertRaisesRegex(ValueError, "invalid_report_reader"):
                review.export_report(source, target, -1)
            if os.geteuid() != 0:
                with self.assertRaisesRegex(ValueError, "owner_operator"):
                    review.export_report(source, target, os.geteuid() + 1)
            self.assertFalse(target.exists())

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

    def ancestry_settings(self):
        value = self.settings()
        value.update(
            schema="dm.source-review-config/v2",
            ancestry={"observer_id": "root", "selector": ANCESTRY},
        )
        value["targets"] = [
            {"id": name, "being_ref": name, "server": server(name), "command": [name]}
            for name in ("child", "root", "outsider")
        ]
        return value

    def ancestry_observation(self, members=("child",), affiliation=("outsider",)):
        value = observed("root")
        claims = [
            {
                "claim_event_id": "claim-" + name,
                "claimant_me_id": name,
                "relations": ["descended-from"],
                "intrinsic_state": "valid-asserted",
                "disposition": "admitted",
            }
            for name in members
        ] + [
            {
                "claim_event_id": "claim-" + name,
                "claimant_me_id": name,
                "relations": ["participates-in"],
                "intrinsic_state": "valid-asserted",
                "disposition": "admitted",
            }
            for name in affiliation
        ]
        value["sources"].append(
            {
                "status": {
                    "schema": "dm.source-status/v0",
                    "selector": ANCESTRY,
                    "observer_me_id": "root",
                    "claims": claims,
                    "eligible_claimants": [
                        {
                            k: x[k]
                            for k in ("claim_event_id", "claimant_me_id", "relations")
                        }
                        for x in claims
                    ],
                    "publications": [],
                },
                "projections": {},
            }
        )
        value["native_calls"] = 2
        return value

    def test_ancestry_selects_admitted_descendants_before_probing_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def call(command, params):
                calls.append((command[0], params["selectors"]))
                if command == ["root"]:
                    return self.ancestry_observation(members=("child", "unconfigured"))
                self.assertEqual(command, ["child"])
                return observed(
                    "child", [{**publication(), "publisher_me_id": "child"}]
                )

            result = review.review(
                self.ancestry_settings(), root / "s", root / "r", call=call, now_ms=1
            )
            self.assertEqual(
                calls, [("root", [SELECTOR, ANCESTRY]), ("child", [SELECTOR])]
            )
            self.assertEqual(result["schema"], "dm.source-review/v2")
            self.assertEqual(
                result["ancestry"]["unconfigured_claimants"],
                [{"being_ref": "unconfigured", "claim_event_id": "claim-unconfigured"}],
            )
            self.assertEqual(
                result["ancestry"]["excluded_targets"],
                [{"target": "outsider", "reason": "not-locally-admitted-descendant"}],
            )
            self.assertEqual(
                [(x["publisher"], x["receiver"], x["state"]) for x in result["offers"]],
                [("child", "root", "offered")],
            )
            self.assertEqual(result["unavailable"], [])
            self.assertEqual(result["model_calls"], 0)
            self.assertFalse(result["automatic_adoption"])

    def test_ancestry_evidence_failure_never_falls_back_to_all_targets(self):
        for failure in ("offline", "wrong-selector", "wrong-observer", "not-admitted"):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                calls = []

                def call(command, _params, *, calls=calls, failure=failure):
                    calls.append(command[0])
                    if failure == "offline":
                        raise TimeoutError
                    value = self.ancestry_observation()
                    if failure == "wrong-selector":
                        value["sources"][1]["status"]["selector"] = SELECTOR
                    elif failure == "wrong-observer":
                        value["sources"][1]["status"]["observer_me_id"] = "other"
                    else:
                        value["sources"][1]["status"]["claims"][0]["disposition"] = (
                            "quarantined"
                        )
                    return value

                result = review.review(
                    self.ancestry_settings(),
                    root / "s",
                    root / "r",
                    call=call,
                    now_ms=1,
                )
                self.assertEqual(calls, ["root"])
                self.assertEqual(result["ancestry"]["state"], "unavailable")
                self.assertTrue(
                    all(
                        x["reason"] == "ancestry-unavailable"
                        for x in result["ancestry"]["excluded_targets"]
                    )
                )
                self.assertEqual(result["unavailable"], ["root"])
                self.assertEqual(
                    result["native_calls"], 2 if failure == "not-admitted" else 0
                )
                self.assertEqual(review.private_read(root / "s")["runs"], 1)

    def test_ancestry_publications_only_participate_when_selected_for_learning(self):
        for learn_ancestry in (False, True):
            with (
                self.subTest(learn_ancestry=learn_ancestry),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                settings = self.ancestry_settings()
                if learn_ancestry:
                    settings["selectors"].append(ANCESTRY)

                def call(
                    command, params, *, learn_ancestry=learn_ancestry, settings=settings
                ):
                    if command == ["root"]:
                        value = self.ancestry_observation()
                        value["sources"][1]["status"]["publications"] = [
                            {**publication(), "publisher_me_id": "root"}
                        ]
                        return value
                    self.assertEqual(command, ["child"])
                    value = observed("child")
                    if learn_ancestry:
                        value["sources"].append(
                            {
                                "status": {
                                    "observer_me_id": "child",
                                    "selector": ANCESTRY,
                                    "claims": [],
                                    "publications": [],
                                },
                                "projections": {},
                            }
                        )
                        value["native_calls"] = 2
                    self.assertEqual(params["selectors"], settings["selectors"])
                    return value

                result = review.review(
                    settings, root / "s", root / "r", call=call, now_ms=1
                )
                self.assertEqual(result["unavailable"], [])
                self.assertEqual(result["local_candidates"], [])
                self.assertEqual(len(result["offers"]), int(learn_ancestry))
                if learn_ancestry:
                    self.assertEqual(
                        result["offers"][0]["source_id"], ANCESTRY["source_id"]
                    )

    def test_ancestry_changes_cursor_without_offers_and_controls_keep_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.ancestry_settings()
            members = ["child"]
            calls = []

            def call(command, _params):
                calls.append(command[0])
                return (
                    self.ancestry_observation(members=members)
                    if command == ["root"]
                    else observed("child")
                )

            def run(now, **kw):
                return review.review(
                    settings, root / "s", root / "r", call=call, now_ms=now, **kw
                )

            first = run(1)
            self.assertEqual(first["offers"], [])
            self.assertEqual(run(60001, control="pause")["native_calls"], 0)
            self.assertEqual(run(60001)["state"], "paused")
            self.assertEqual(run(60001, control="resume")["runs"], 1)
            members.clear()
            second = run(60001)
            self.assertTrue(second["changed"])
            self.assertNotEqual(first["cursor"], second["cursor"])
            self.assertEqual(calls, ["root", "child", "root"])
            self.assertEqual(run(120001)["state"], "finished")
            settings["ancestry"]["selector"] = SELECTOR
            with self.assertRaisesRegex(ValueError, "config_changed"):
                run(120001)

    def test_ancestry_configuration_keeps_existing_selector_and_target_limits(self):
        settings = self.ancestry_settings()
        review.config(settings)
        for mutate in (
            lambda x: x["ancestry"].update(observer_id="absent"),
            lambda x: x.update(schema="dm.source-review-config/v1"),
            lambda x: x.update(selectors=[SELECTOR] * 8),
            lambda x: x["ancestry"]["selector"].update(source_id="invalid"),
        ):
            value = copy.deepcopy(settings)
            mutate(value)
            with self.assertRaises(ValueError):
                review.config(value)

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
