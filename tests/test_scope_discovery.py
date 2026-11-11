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
            authority_observed_at_ms=1,
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


class EveryoneDiscoveryTests(unittest.TestCase):
    def contact(self, name):
        return {
            "schema": "dm.human-endpoint/v1",
            "scope": "/human",
            "source": "shared-resource-access-pairing",
            "home_ref": "home:" + name,
            "owner_being_ref": name,
            "human": {
                "ref": "provider-human:shared",
                "kind": "human",
                "name": "Pair",
                "revision": "r1",
            },
            "applications": [
                {
                    "capability": "interaction",
                    "url": f"https://{name}.example/interaction/",
                    "state": "configured",
                }
            ],
            "route_state": "configured",
            "human_presence": "not-observed",
            "delivery": "not-requested",
            "native_membership": "not-implied",
        }

    def contact_discovery(self, transform=lambda name, value: value):
        calls = []

        def call(command, request):
            name = command[0]
            calls.append((name, request["view"]))
            self.assertEqual(request["view"], "contacts")
            value = response(name, "body", request["request_id"])
            value.update(
                schema="dm.scope-contact-probe/v1",
                human_endpoint=self.contact(name),
                home_read_attempted=True,
            )
            return transform(name, value)

        return near.everyone(
            settings(), include_humans=True, call=call, now_ms=1, clock=lambda: 0
        ), calls

    def test_explicit_contacts_preserve_provider_kind_and_each_pair_association(self):
        result, calls = self.contact_discovery()
        self.assertEqual(result["schema"], "dm.scope.everyone/v2")
        self.assertEqual(len(result["members"]), 2)
        self.assertEqual(len(result["human_contacts"]), 2)
        self.assertEqual(result["confirmed_home_reads"], 2)
        self.assertEqual(result["confirmed_native_calls"], 2)
        self.assertEqual(result["unconfirmed_home_reads"], 0)
        self.assertEqual(len(calls), 2)
        # The same human may have distinct pairs/routes; never merge their beings.
        self.assertEqual(
            {r["endpoint"]["human"]["ref"] for r in result["human_contacts"]},
            {"provider-human:shared"},
        )
        self.assertEqual(
            {r["via_being_ref"] for r in result["human_contacts"]}, {"root", "child"}
        )
        self.assertTrue(
            all(
                r["reachability"] == "configured-route-not-probed"
                for r in result["human_contacts"]
            )
        )
        self.assertTrue(result["partial"])
        self.assertEqual(result["model_calls"], 0)

    def test_bad_or_unavailable_home_does_not_erase_native_body_or_disclose_contact(
        self,
    ):
        for failure in (
            "foreign-owner",
            "native-identity",
            "credential-url",
            "claimed-delivery",
            "missing",
            "capacity",
        ):

            def changed(name, value, failure=failure):
                if name == "child":
                    contact = value["human_endpoint"]
                    if failure == "foreign-owner":
                        contact["owner_being_ref"] = "foreign"
                    elif failure == "native-identity":
                        contact["human"]["kind"] = "being"
                    elif failure == "credential-url":
                        contact["applications"][0]["url"] = (
                            "https://user:secret@child.example/interaction/"
                        )
                    elif failure == "claimed-delivery":
                        contact["delivery"] = "delivered"
                    elif failure == "missing":
                        value["human_endpoint"] = None
                    else:
                        contact["applications"] *= 33
                return value

            with self.subTest(failure=failure):
                result, _ = self.contact_discovery(changed)
                self.assertEqual(len(result["members"]), 2)
                self.assertEqual(len(result["human_contacts"]), 1)
                self.assertEqual(result["confirmed_home_reads"], 1)
                self.assertEqual(result["unconfirmed_home_reads"], 1)
                self.assertEqual(result["human_unavailable"][0]["id"], "child")
                self.assertNotIn("secret", json.dumps(result))

    def test_missing_client_and_unconfigured_routes_remain_distinct(self):
        def missing(name, value):
            if name == "child":
                value.update(human_endpoint=None, home_read_attempted=False)
            else:
                value["human_endpoint"].update(
                    applications=[], route_state="unconfigured"
                )
            return value

        result, _ = self.contact_discovery(missing)
        self.assertEqual(len(result["members"]), 2)
        self.assertEqual(
            result["human_contacts"][0]["reachability"], "route-unconfigured"
        )
        self.assertEqual(result["unconfirmed_home_reads"], 0)
        self.assertEqual(len(result["human_unavailable"]), 1)

    def test_implicit_truthy_selection_is_rejected_before_any_read(self):
        for selection in (None, 1, "yes"):
            with self.assertRaisesRegex(
                ValueError, "explicit_human_selection_required"
            ):
                near.everyone(
                    settings(),
                    include_humans=selection,
                    call=lambda *_: self.fail("Unexpected read"),
                    now_ms=1,
                )

    def test_reachable_nonmember_is_observed_without_inventory_or_model(self):
        calls = []
        config = settings()
        config["targets"].append(target("not-admitted"))

        def call(command, request):
            self.assertEqual(request["view"], "body")
            calls.append(command[0])
            return response(command[0], request["view"], request["request_id"])

        result = near.everyone(config, call=call, now_ms=1, clock=lambda: 0)
        self.assertEqual(set(calls), {"root", "child", "not-admitted"})
        self.assertEqual(result["scope"], "/everyone")
        self.assertEqual(len(result["members"]), 3)
        self.assertEqual(result["confirmed_native_calls"], 3)
        self.assertEqual(result["native_call_ceiling"], 3)
        self.assertEqual(result["model_calls"], 0)
        self.assertEqual(result["membership"], "not-inferred")
        self.assertTrue(result["partial"])
        self.assertEqual(result["coverage"]["humans"], "not-configured")
        self.assertEqual(result["process_response"], "not-observed")
        self.assertNotIn("command", json.dumps(result))

    def test_wrong_identity_refusal_and_deadline_never_become_reachable(self):
        for failure in ("identity", "refusal", "surface", "deadline"):
            clock = Clock()

            def call(command, request, failure=failure, clock=clock):
                name = command[0]
                result = response(name, request["view"], request["request_id"])
                if name == "child":
                    if failure == "refusal":
                        raise RuntimeError("native refused")
                    if failure == "identity":
                        result["server"] = server("foreign")
                    if failure == "surface":
                        result["value"]["surface"]["body_ref"] = "foreign"
                    if failure == "deadline":
                        clock.local.value = 100_000_000_000
                return result

            with self.subTest(failure=failure):
                result = near.everyone(settings(), call=call, now_ms=1, clock=clock)
                self.assertEqual([r["id"] for r in result["members"]], ["root"])
                self.assertEqual(result["unavailable"][0]["id"], "child")
                self.assertEqual(result["unconfirmed_probes"], 1)

    def test_expired_configuration_probes_nothing(self):
        def forbidden(*args):
            self.fail("expired configuration must not probe")

        with self.assertRaisesRegex(ValueError, "scope_probe_expired"):
            near.everyone(settings(), call=forbidden, now_ms=100000)


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

    def test_partial_omission_is_unknown_and_never_probed(self):
        def truncated(name, view, value):
            if view == "inventory":
                value["value"]["partial"] = True
                value["value"]["members"] = [member("root")]
            return value

        result, calls = self.run_discovery(truncated)
        self.assertTrue(result["partial"])
        self.assertEqual(
            result["unavailable"],
            [{"id": "child", "reason": "membership-unknown-partial-inventory"}],
        )
        self.assertFalse(any(name == "child" for name, _ in calls))
        self.assertEqual(result["excluded"], [])

    def test_authority_clock_offsets_do_not_change_proximity(self):
        for offset in (-1, 1000000000000):

            def shifted(name, view, value, offset=offset):
                if view == "inventory":
                    value["value"]["authority_observed_at_ms"] += offset
                    for row in value["value"]["members"]:
                        row["lease_expires_at_ms"] += offset
                return value

            result, _ = self.run_discovery(shifted)
            self.assertFalse(result["partial"])
            self.assertEqual([row["id"] for row in result["members"]], ["root"])
            self.assertEqual(result["excluded"][0]["elapsed_ms"], 900)

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


def resource_settings():
    value = settings()
    value["resources"] = [{"resource_ref": "host-device", "command": ["device-owner"]}]
    return value


def device_report():
    return dict(
        schema="dm.integrator-discovery/v1",
        resource_ref="host-device",
        evaluated_at=1,
        integrator=dict(state="observed", observed_at=1),
        perceptors=[
            dict(
                id="camera",
                resource_ref="host-device",
                state="no-use-detected",
                observed_at=1,
                fresh=True,
                coverage_complete=True,
                media_read=False,
                private_process="must-not-leave",
            )
        ],
        actuators=[
            dict(
                id="panel-view",
                commands=[["view", "compact"], ["view", "expanded"]],
                permission="existing-owner-control-required",
                executed=False,
                requested_compact=True,
                observed_compact=False,
            )
        ],
        limits=dict(
            model_calls=0, device_capture_started=False, controls_executed=False
        ),
        private_output_path="must-not-leave",
    )


class ResourceDiscoveryTests(unittest.TestCase):
    def observe(self, report=None, scope="/integrators", native=None):
        calls = []

        def call(command, request):
            calls.append((command, request))
            if command == ["root"]:
                return (
                    native
                    if native is not None
                    else response("root", "body", request["request_id"])
                )
            return report if report is not None else device_report()

        result = near.resource_discovery(
            resource_settings(),
            scope=scope,
            resource_ref="host-device",
            now_ms=1000,
            call=call,
        )
        return result, calls

    def test_resource_is_associated_with_actual_native_observer_and_filtered(self):
        result, calls = self.observe()
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["observer"], server("root"))
        self.assertEqual(result["confirmed_native_calls"], 1)
        self.assertEqual(result["confirmed_resource_reads"], 1)
        self.assertFalse(result["partial"])
        self.assertNotIn("must-not-leave", json.dumps(result))
        self.assertEqual(result["resource_ownership"], "not-established-by-discovery")
        control = result["members"][0]["actuators"][0]
        self.assertTrue(control["requested_compact"])
        self.assertFalse(control["observed_compact"])
        for scope, identifier in [
            ("/perceptors", "camera"),
            ("/actuators", "panel-view"),
        ]:
            with self.subTest(scope=scope):
                result, _ = self.observe(scope=scope)
                self.assertEqual(result["members"][0]["id"], identifier)
                self.assertEqual(result["model_calls"], 0)

    def test_stale_hub_returns_partial_unknown_observations(self):
        value = device_report()
        value["integrator"].update(state="stale", observed_at=0)
        value["perceptors"][0].update(
            state="unknown", fresh=False, coverage_complete=False
        )
        value["actuators"][0].update(requested_compact=None, observed_compact=None)
        result, calls = self.observe(report=value)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["confirmed_resource_reads"], 1)
        self.assertTrue(result["partial"])
        self.assertEqual(result["members"][0]["perceptors"][0]["state"], "unknown")

    def test_native_rejection_prevents_resource_call(self):
        result, calls = self.observe(native=response("foreign", "body", "unused"))
        self.assertEqual(len(calls), 1)
        self.assertTrue(result["partial"])
        self.assertFalse(result["members"])
        self.assertEqual(result["confirmed_resource_reads"], 0)

    def test_stale_negative_and_unexpected_effects_never_become_device_evidence(self):
        variants = []
        value = device_report()
        value["resource_ref"] = "another"
        variants.append(value)
        value = device_report()
        value["evaluated_at"] = -100
        variants.append(value)
        value = device_report()
        value["limits"]["controls_executed"] = True
        variants.append(value)
        value = device_report()
        value["control"] = {"outcome": "uncertain"}
        variants.append(value)
        value = device_report()
        value["perceptors"][0]["coverage_complete"] = False
        variants.append(value)
        value = device_report()
        value["perceptors"][0]["fresh"] = False
        variants.append(value)
        value = device_report()
        value["integrator"]["observed_at"] = -10
        variants.append(value)
        for value in variants:
            with self.subTest(value=value):
                result, calls = self.observe(report=value)
                self.assertEqual(len(calls), 2)
                self.assertTrue(result["partial"])
                self.assertFalse(result["members"])
                self.assertEqual(result["confirmed_resource_reads"], 0)

    def test_missing_selection_and_expiry_do_not_call_any_owner(self):
        def never(*args):
            self.fail("unexpected call")

        with self.assertRaisesRegex(ValueError, "resource_route_not_selected"):
            near.resource_discovery(
                settings(),
                scope="/integrators",
                resource_ref="host-device",
                now_ms=1000,
                call=never,
            )
        with self.assertRaisesRegex(ValueError, "scope_probe_expired"):
            near.resource_discovery(
                resource_settings(),
                scope="/integrators",
                resource_ref="host-device",
                now_ms=100000,
                call=never,
            )


class RealmControlTests(unittest.TestCase):
    unit = "matrix-work-" + "a" * 32 + ".service"
    invocation = "b" * 32

    def properties(self):
        return dict(
            Id=self.unit,
            InvocationID=self.invocation,
            ActiveState="active",
            Transient="yes",
            Restart="no",
            NoNewPrivileges="yes",
            KillMode="control-group",
            ControlGroup="/user.slice/task.service",
            MemoryMax="134217728",
            TasksMax="16",
            RuntimeMaxUSec="1min",
            CPUQuotaPerSecUSec="250ms",
        )

    def run_control(
        self,
        action="inspect",
        report=None,
        fail=False,
        change=None,
        foreign=False,
        invocation=None,
    ):
        calls = []
        properties = self.properties()
        if change:
            properties.update(change)
        state = {"cpu": "25000 100000", "stopped": False}

        def manager(args):
            calls.append(args)
            if args[0] == "show":
                return "\n".join(k + "=" + v for k, v in properties.items())
            if fail:
                raise TimeoutError("actual outcome unknown")
            if args[0] == "set-property":
                state["cpu"] = "50000 100000"
            if args[0] == "stop":
                state["stopped"] = True
            return ""

        def kernel(group):
            return (
                None
                if state["stopped"]
                else {
                    "cpu.max": state["cpu"],
                    "memory.max": "134217728",
                    "pids.max": "16",
                }
            )

        result = near.realm_control(
            Path("unused"),
            unit=self.unit,
            action=action,
            invocation=invocation or (self.invocation if action != "inspect" else None),
            cpu_percent=50 if action == "cpu" else None,
            report=report,
            manager=manager,
            native_probe=lambda *a: response("root", "body", "unused"),
            surface=lambda: "dm:surface:v1:" + ("f" if foreign else "a") * 64,
            kernel=kernel,
        )
        return result, calls

    def test_discovery_and_cpu_change_keep_native_identity_and_kernel_evidence(self):
        value, calls = self.run_control()
        self.assertEqual(value["scope"], "/realm.controls")
        self.assertEqual(value["observer"], server("root"))
        self.assertEqual(len(calls), 1)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "effect.json"
            value, calls = self.run_control("cpu", report=path)
            self.assertEqual(value["phase"], "cpu_applied_verified")
            self.assertEqual(value["kernel_limits"]["cpu.max"], "50000 100000")
            self.assertEqual(json.loads(path.read_text()), value)
            self.assertEqual(
                calls[1], ["set-property", "--runtime", self.unit, "CPUQuota=50%"]
            )
            with self.assertRaises(FileExistsError):
                self.run_control("cpu", report=path)
            with self.assertRaisesRegex(ValueError, "receipt_must_be_preserved"):
                self.run_control("inspect", report=path)

    def test_owner_stop_checks_actual_cgroup_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            value, calls = self.run_control("stop", report=Path(folder) / "stop.json")
            self.assertEqual(value["phase"], "stopped_cgroup_removed")
            self.assertIsNone(value["kernel_limits"])
            self.assertEqual(calls[-1], ["stop", self.unit])

    def test_lost_response_retains_intent_without_replaying_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "unknown.json"
            with self.assertRaises(TimeoutError):
                self.run_control("cpu", report=path, fail=True)
            self.assertEqual(
                json.loads(path.read_text())["phase"],
                "inspect_retained_outcome_no_replay",
            )
            with self.assertRaises(FileExistsError):
                self.run_control("cpu", report=path)

    def test_foreign_surface_changed_invocation_and_nonwork_service_refuse(self):
        with self.assertRaisesRegex(ValueError, "local_native_body"):
            self.run_control(foreign=True)
        with self.assertRaisesRegex(ValueError, "invocation_changed"):
            self.run_control(invocation="c" * 32)
        for change in (
            {"Transient": "no"},
            {"Restart": "always"},
            {"RuntimeMaxUSec": "infinity"},
            {"MemoryMax": "infinity"},
            {"NoNewPrivileges": "no"},
            {"KillMode": "process"},
        ):
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "bounded_work"),
            ):
                self.run_control(change=change)
        with self.assertRaisesRegex(ValueError, "selected_work"):
            near.realm_control(Path("unused"), unit="compaii-telegram.service")
