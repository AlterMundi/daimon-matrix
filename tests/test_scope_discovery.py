"""Explicit /near domains, admitted identities and actual bounded process I/O."""

import copy
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from tools import scope_discovery as near


def server(name):
    return {key: name + ":" + key for key in near.SERVER}


def target(name):
    return {"id": name, "being_ref": name, "server": server(name), "command": [name]}


def settings():
    return {
        "schema": "dm.scope-probe-config/v1",
        "observer_id": "root",
        "expires_at_ms": 100000,
        "targets": [target("root"), target("child")],
    }


def member(name):
    return {
        "being_ref": name,
        **{key: value for key, value in server(name).items() if key in near.ORIGIN},
        "lease_expires_at_ms": 50000,
    }


def response(name, view, request_id):
    value = {"being_ref": name, "origin": server(name)}
    if view == "inventory":
        value.update(
            schema="dm.scope.discovery/v1",
            scope="/all",
            request_id=request_id,
            partial=False,
            members=[member("root"), member("child")],
        )
    else:
        value.update(
            schema="dm.scope.me-surface/v1",
            evaluated_at_ms=1,
            surface={
                "schema": "dm.cluster-surface-snapshot/v1",
                **{k: v for k, v in server(name).items() if k in near.ORIGIN},
                "domain": "native-linux-os",
                "state": "running",
                "surface_ref": "dm:surface:v1:" + "a" * 64,
                "observed_at_ms": 1,
            },
        )
    return {
        "schema": "dm.scope-probe/v1",
        "server": server(name),
        "native_calls": 1,
        "value": value,
    }


class Clock:
    def __init__(self):
        self.local = threading.local()

    def __call__(self):
        return getattr(self.local, "value", 0)


class NearDiscoveryTests(unittest.TestCase):
    def run_discovery(
        self, transform=lambda name, view, value: value, config=None, threshold=100
    ):
        clock = Clock()
        calls = []

        def call(command, request):
            name = command[0]
            calls.append((name, request["view"]))
            clock.local.value = clock() + (
                10_000_000 if name == "root" else 900_000_000
            )
            return transform(
                name,
                request["view"],
                response(name, request["view"], request["request_id"]),
            )

        result = near.discover(
            settings() if config is None else config,
            domain=near.DOMAIN,
            within_ms=threshold,
            call=call,
            now_ms=1,
            clock=clock,
        )
        return result, calls

    def test_explicit_route_measurement_is_not_physical_distance_or_model_reply(self):
        result, calls = self.run_discovery()
        self.assertEqual([row["id"] for row in result["members"]], ["root"])
        self.assertEqual(result["excluded"][0]["id"], "child")
        self.assertEqual(result["excluded"][0]["elapsed_ms"], 900)
        self.assertEqual(result["excluded"][0]["reason"], "outside-threshold")
        self.assertEqual(result["confirmed_native_calls"], 3)
        self.assertEqual(result["process_response"], "not-observed")
        self.assertFalse(result["partial"])
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(result["domain"], "authenticated-control-route-ms")

    def test_wrong_or_missing_domain_threshold_and_expiry_make_no_calls(self):
        for domain, threshold, now in [
            ("geography", 1, 1),
            (near.DOMAIN, True, 1),
            (near.DOMAIN, 40001, 1),
            (near.DOMAIN, 1, 100000),
        ]:
            with self.subTest(domain=domain, threshold=threshold, now=now):

                def forbidden(*args):
                    self.fail("invalid contract must not probe")

                with self.assertRaises(ValueError):
                    near.discover(
                        settings(),
                        domain=domain,
                        within_ms=threshold,
                        call=forbidden,
                        now_ms=now,
                    )

    def test_inventory_failures_prevent_peer_probes(self):
        def malformed(name, view, value):
            if view == "inventory":
                value["value"]["origin"] = server("foreign")
            return value

        result, calls = self.run_discovery(malformed)
        self.assertEqual(calls, [("root", "inventory")])
        self.assertTrue(result["partial"])
        self.assertEqual(result["members"], [])
        self.assertEqual(result["confirmed_native_calls"], 0)
        self.assertEqual(result["unconfirmed_probes"], 1)

    def test_admitted_without_route_is_not_a_remote_outage(self):
        def added(name, view, value):
            if view == "inventory":
                value["value"]["members"].append(member("unconfigured"))
            return value

        result, calls = self.run_discovery(added)
        self.assertEqual(result["unconfigured"][0]["being_ref"], "unconfigured")
        self.assertTrue(result["partial"])
        self.assertEqual(result["unavailable"], [])
        self.assertFalse(any(name == "unconfigured" for name, _ in calls))

    def test_configured_nonmember_is_excluded_before_probe(self):
        config = settings()
        config["targets"].append(target("not-admitted"))
        result, calls = self.run_discovery(config=config)
        self.assertIn(
            {"id": "not-admitted", "reason": "not-in-current-admission"},
            result["excluded"],
        )
        self.assertFalse(any(name == "not-admitted" for name, _ in calls))

    def test_body_mismatch_never_becomes_zero_distance(self):
        def changed(name, view, value):
            if name == "child" and view == "body":
                value["server"]["incarnation_id"] = "different"
            return value

        result, _ = self.run_discovery(changed)
        self.assertEqual(result["unavailable"][0]["id"], "child")
        self.assertNotIn("elapsed_ms", result["unavailable"][0])
        self.assertTrue(result["partial"])
        self.assertEqual(result["unconfirmed_probes"], 1)
        self.assertEqual(result["confirmed_native_calls"], 2)

    def test_wrong_surface_or_admission_expiring_during_probe_stays_unknown(self):
        for case in ("surface", "expiry"):

            def changed(name, view, value, case=case):
                if case == "surface" and view == "body" and name == "child":
                    value["value"]["surface"]["body_ref"] = "foreign"
                if case == "expiry" and view == "inventory":
                    value["value"]["members"][1]["lease_expires_at_ms"] = 500
                return value

            result, _ = self.run_discovery(changed)
            self.assertTrue(result["partial"])
            self.assertEqual(result["unavailable"][0]["id"], "child")
            self.assertNotIn("elapsed_ms", result["unavailable"][0])

    def test_duplicate_target_and_expired_or_duplicate_admission_refuse(self):
        config = settings()
        config["targets"].append(copy.deepcopy(config["targets"][0]))
        with self.assertRaises(ValueError):
            self.run_discovery(config=config)
        for mode in ("expired", "duplicate", "no-observer"):

            def changed(name, view, value, mode=mode):
                if view == "inventory":
                    if mode == "expired":
                        value["value"]["members"][1]["lease_expires_at_ms"] = 1
                    elif mode == "duplicate":
                        value["value"]["members"].append(member("root"))
                    else:
                        value["value"]["members"] = [member("child")]
                return value

            result, calls = self.run_discovery(changed)
            self.assertTrue(result["partial"])
            self.assertEqual(calls, [("root", "inventory")])

    def test_actual_owned_process_boundary_and_latest_report(self):
        config = settings()
        config["targets"] = [target("root")]
        records = {
            view: response("root", view, "unused") for view in ("inventory", "body")
        }
        records["inventory"]["value"]["members"] = [member("root")]
        code = (
            "import json,sys\n"
            + "records="
            + repr(records)
            + "\n"
            + "query=json.load(sys.stdin)\n"
            + "value=records[query['view']]\n"
            + "if query['view']=='inventory':\n"
            + " value['value']['request_id']=query['request_id']\n"
            + "print(json.dumps(value))\n"
        )
        config["targets"][0]["command"] = [sys.executable, "-c", code]
        result = near.discover(config, domain=near.DOMAIN, within_ms=40000, now_ms=1)
        self.assertEqual(result["confirmed_native_calls"], 2)
        self.assertFalse(result["partial"])
        self.assertGreater(result["members"][0]["elapsed_ms"], 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "latest.json"
            near.write(path, result)
            near.write(path, result)
            self.assertEqual(json.loads(path.read_text()), result)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)
