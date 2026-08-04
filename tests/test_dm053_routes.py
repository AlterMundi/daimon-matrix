from __future__ import annotations

import copy
import hashlib
import json
import socket
import threading
import unittest
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
)

from daimon_matrix.canonical import b64url, canonical_bytes, unb64url
from daimon_matrix.communication import (
    MESSAGE_PAYLOAD_SCHEMA,
    RESOLUTION_PAYLOAD_SCHEMA,
    CommunicationError,
    CommunicationStore,
)
from daimon_matrix.daemon import serve_connection
from daimon_matrix.local_api import (
    create_capability,
    create_request,
    decode_frame,
    encode_frame,
    request_hash,
    verify_response,
)
from daimon_matrix.routes import (
    GATEWAY_POLICY_SCHEMA,
    PROVIDER_RESULT_SCHEMA,
    ROUTE_BINDING_SCHEMA,
    ROUTE_PROFILE_SCHEMA,
    AuthenticatedProvider,
    DirectHTTPProvider,
    GatewayPolicy,
    LocalIPCProvider,
    OpaqueInbox,
    RouteCoordinator,
    RouteError,
    RouteProfile,
    TransportIngress,
    gateway_proposal,
    render_gateway,
    serve_transport_connection,
)
from daimon_matrix.runtime import HostedRuntime
from daimon_matrix.sealed import (
    DisclosureAuthorization,
    open_event,
    recipient_descriptor,
    seal_event,
    sender_descriptor,
)
from daimon_matrix.service import HostedWeave
from tests.test_dm022_ledger import NOW
from tests.test_dm051_sealed import SealedFixture

ROOT = Path(__file__).resolve().parents[1]


def identifier(prefix: int, index: int) -> str:
    return f"{prefix:08d}-0000-4000-8000-{index:012d}"


def _test_manifest(
    provider_ref: str, route_ref: str, route_class: str
) -> dict[str, Any]:
    return {
        "schema": "dm.route-provider-manifest/v1",
        "provider_ref": provider_ref,
        "route_ref": route_ref,
        "route_class": route_class,
        "versions": ["v1"],
        "operations": ["inspect", "submit"],
        "limits": {
            "max_input_bytes": 5 * 1024 * 1024,
            "max_output_bytes": 5 * 1024 * 1024,
            "max_runtime_ms": 30_000,
        },
        "authority": {
            "matrix_authority": False,
            "may_append_ledger": False,
            "may_issue_presence": False,
            "may_mint_membership": False,
            "may_sign_as_me": False,
        },
    }


class RouteFixture(SealedFixture):
    def setUp(self) -> None:
        super().setUp()
        self.now = NOW + 1
        self.store = CommunicationStore(self.ledger_a, clock=lambda: self.now)
        self.store.initialize()
        self.secret = hashlib.sha256(b"dm053 synthetic transport credential").digest()
        self.calls: list[str] = []

    def message_and_delivery(
        self, *, recipients: tuple[str, ...] = ("daimonmatrix",)
    ) -> tuple[dict[str, Any], dict[str, Any], bytes, DisclosureAuthorization]:
        message = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication",
            payload={
                "schema": MESSAGE_PAYLOAD_SCHEMA,
                "intent": {
                    "operation": "message.send",
                    "scope": "/we",
                    "thread_id": identifier(71_000_000, 1),
                },
                "body": {"text": "route me, not my authority"},
                "reply": None,
            },
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )
        targets = [
            {
                "scope_kind": "we",
                "recipient_type": "embodiment",
                "recipient_id": f"embodiment:{label}",
                "receipt_origin_embodiment_id": f"embodiment:{label}",
                "evidence_cursor": "dm:evidence:v1:synthetic-resolution",
            }
            for label in recipients
        ]
        resolution = self.ledger_a.append_local(
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": sorted(
                    targets,
                    key=lambda row: (row["recipient_type"], row["recipient_id"]),
                ),
            },
            signer=self.signers["legion"],
            causal_parents=[message["event_id"]],
            occurred_at_ms=NOW,
        )
        result = self.store.accept(
            message_event_id=message["event_id"],
            resolution_event_id=resolution["event_id"],
        )
        recipient_targets = [self.targets[label] for label in recipients]
        recipient_rows = sorted(
            (recipient_descriptor(target, at_ms=NOW) for target in recipient_targets),
            key=lambda row: (
                row["being_ref"],
                row["embodiment_id"],
                row["encryption_kid"],
            ),
        )
        authorization = DisclosureAuthorization.synthetic(
            event=message,
            sender=sender_descriptor(message, self.authority, at_ms=NOW),
            recipients=recipient_rows,
            evidence_hash=hashlib.sha256(b"dm053 resolution evidence").hexdigest(),
            authorized_at_ms=NOW,
            expires_at_ms=NOW + 60_000,
            authorization_id=identifier(71_000_000, 2),
        )
        raw = seal_event(
            message,
            sender_authority=self.authority,
            recipients=recipient_targets,
            authorization=authorization,
            custody=self.custodies["legion"],
            issued_at_ms=NOW,
            expires_at_ms=NOW + 30_000,
        )
        return message, result, raw, authorization

    def profile(
        self,
        rows: list[dict[str, Any]],
        *,
        principal_id: str = "compaii@remote",
        local_recipient_ids: list[str] | None = None,
        enabled: bool = True,
    ) -> RouteProfile:
        return RouteProfile.from_value(
            {
                "schema": ROUTE_PROFILE_SCHEMA,
                "profile_id": "route-profile:legion",
                "body_ref": "body:legion",
                "principal_id": principal_id,
                "policy_version": "dm.route-policy/v1",
                "enabled": enabled,
                "local_recipient_ids": sorted(local_recipient_ids or []),
                "routes": rows,
            }
        )

    def binding(
        self,
        provider_ref: str,
        route_ref: str,
        route_class: str,
        *,
        priority: int,
        recipient_id: str = "embodiment:daimonmatrix",
        recipient_body_ref: str = "body:daimonmatrix",
    ) -> dict[str, Any]:
        return {
            "schema": ROUTE_BINDING_SCHEMA,
            "adapter_id": f"adapter:{provider_ref.rsplit(':', 1)[-1]}",
            "provider_ref": provider_ref,
            "route_ref": route_ref,
            "route_class": route_class,
            "priority": priority,
            "recipient_id": recipient_id,
            "recipient_body_ref": recipient_body_ref,
            "credential_ref": f"credential:{provider_ref.rsplit(':', 1)[-1]}",
            "enabled": True,
        }

    def validator(
        self,
        authorization: DisclosureAuthorization,
        recipients: tuple[str, ...] = ("daimonmatrix",),
    ) -> Callable[[bytes], None]:
        def validate(raw: bytes) -> None:
            open_event(
                raw,
                sender_authority=self.authority,
                local_target=self.targets["daimonmatrix"],
                recipient_targets=[self.targets[label] for label in recipients],
                authorization=authorization,
                custody=self.custodies["daimonmatrix"],
                at_ms=self.now,
            )

        return validate

    def ingress(
        self,
        name: str,
        authorization: DisclosureAuthorization,
        *,
        hub: bool = False,
        presence_ref: str | None = None,
        fence_ref: str | None = None,
    ) -> tuple[OpaqueInbox, TransportIngress]:
        directory = self.root_path / f"provider-{name}"
        directory.mkdir(mode=0o700)
        inbox = OpaqueInbox(directory / "inbox.sqlite", clock=lambda: self.now)
        ingress = TransportIngress(
            provider_ref=f"provider:{name}",
            route_ref=f"route:{name}",
            key_ref=f"credential:{name}",
            secret=self.secret,
            recipient_id="embodiment:daimonmatrix",
            recipient_body_ref="body:daimonmatrix",
            inbox=inbox,
            clock=lambda: self.now,
            hub=hub,
            presence_ref=presence_ref,
            fence_ref=fence_ref,
            intake_validator=None if hub else self.validator(authorization),
            intake_gate=(
                (lambda _presence, _fence: None) if presence_ref is not None else None
            ),
        )
        return inbox, ingress

    def provider(
        self,
        name: str,
        route_class: str,
        round_trip: Any,
        *,
        available: bool = True,
    ) -> AuthenticatedProvider:
        return AuthenticatedProvider(
            provider_ref=f"provider:{name}",
            route_ref=f"route:{name}",
            route_class=route_class,
            key_ref=f"credential:{name}",
            secret=self.secret,
            sender_principal="compaii@remote",
            sender_body_ref="body:legion",
            round_trip=round_trip,
            clock=lambda: self.now,
            available=available,
        )


class RouteSelectionTests(RouteFixture):
    def test_candidate_order_is_input_order_independent(self) -> None:
        _, result, _, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        rows = [
            self.binding("provider:hub", "route:hub", "hub", priority=0),
            self.binding("provider:z", "route:z", "direct", priority=7),
            self.binding("provider:a", "route:a", "direct", priority=7),
            self.binding("provider:vpn", "route:vpn", "direct-anyvpn", priority=9),
        ]
        providers = {}
        for name, route_class in (
            ("hub", "hub"),
            ("z", "direct"),
            ("a", "direct"),
            ("vpn", "direct-anyvpn"),
        ):
            _, ingress = self.ingress(name, authorization, hub=name == "hub")
            providers[f"provider:{name}"] = self.provider(
                name, route_class, ingress.handle
            )
        first = RouteCoordinator(
            self.store, self.profile(rows), providers, clock=lambda: self.now
        ).inspect(leg_id=leg_id)
        second = RouteCoordinator(
            self.store,
            self.profile(list(reversed(rows))),
            providers,
            clock=lambda: self.now,
        ).inspect(leg_id=leg_id)
        expected = ["route:vpn", "route:a", "route:z", "route:hub"]
        self.assertEqual([row["route_ref"] for row in first["candidates"]], expected)
        self.assertEqual(first, second)

    def test_direct_success_records_route_ack_but_not_semantic_delivery(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg = result["legs"][0]
        inbox, ingress = self.ingress(
            "direct",
            authorization,
            presence_ref="presence:current",
            fence_ref="fence:resource-current",
        )
        provider = self.provider("direct", "direct", ingress.handle)
        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [self.binding("provider:direct", "route:direct", "direct", priority=0)]
            ),
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        dispatched = coordinator.dispatch(
            leg_id=leg["leg_id"], envelope=raw, deadline_ms=NOW + 20_000
        )
        self.assertEqual(dispatched["status"], "accepted")
        self.assertEqual(dispatched["selected"]["outcome"], "recipient-intake")
        self.assertEqual(
            dispatched["selected"]["intake"]["presence_ref"], "presence:current"
        )
        self.assertEqual(
            dispatched["selected"]["intake"]["fence_ref"],
            "fence:resource-current",
        )
        self.assertEqual(self.store.leg(leg["leg_id"])["state"], "accepted")
        document = json.loads(raw)
        claim = inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:recipient",
            claim_id=identifier(72_000_000, 1),
            limit=100,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(
            [item["delivery_id"] for item in claim["items"]], [document["delivery_id"]]
        )

    def test_unavailable_direct_falls_back_to_hub_but_refusal_does_not(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        direct = self.provider("direct", "direct", lambda _: b"unused", available=False)
        hub_inbox, hub_ingress = self.ingress("hub", authorization, hub=True)
        hub = self.provider("hub", "hub", hub_ingress.handle)
        rows = [
            self.binding("provider:direct", "route:direct", "direct", priority=0),
            self.binding("provider:hub", "route:hub", "hub", priority=0),
        ]
        coordinator = RouteCoordinator(
            self.store,
            self.profile(rows),
            {direct.provider_ref: direct, hub.provider_ref: hub},
            clock=lambda: self.now,
        )
        dispatched = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        self.assertEqual(dispatched["status"], "accepted")
        self.assertEqual(dispatched["selected"]["outcome"], "hub-accepted")
        self.assertEqual(
            [row["status"] for row in dispatched["attempts"]],
            ["unavailable", "accepted"],
        )
        claimed = hub_inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:hub",
            claim_id=identifier(72_000_000, 2),
            limit=1,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(len(claimed["items"]), 1)

    def test_all_unavailable_stays_pending_and_new_deadline_can_recover(
        self,
    ) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        binding = self.binding("provider:direct", "route:direct", "direct", priority=0)
        unavailable = self.provider(
            "direct", "direct", lambda _: b"unused", available=False
        )
        first = RouteCoordinator(
            self.store,
            self.profile([binding]),
            {unavailable.provider_ref: unavailable},
            clock=lambda: self.now,
        ).dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)
        self.assertEqual(first["status"], "pending")
        self.assertIsNone(first["selected"])

        _, ingress = self.ingress("direct", authorization)
        available = self.provider("direct", "direct", ingress.handle)
        recovered = RouteCoordinator(
            self.store,
            self.profile([binding]),
            {available.provider_ref: available},
            clock=lambda: self.now,
        ).dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 21_000)
        self.assertEqual(recovered["status"], "accepted")
        self.assertNotEqual(
            first["attempts"][0]["attempt_id"],
            recovered["attempts"][0]["attempt_id"],
        )

    def test_missing_route_is_unroutable_without_provider_effect(self) -> None:
        _, result, raw, _ = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        coordinator = RouteCoordinator(
            self.store,
            self.profile([]),
            {},
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(RouteError, "route_unroutable"):
            coordinator.dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)
        self.assertEqual(self.store.leg(leg_id)["state"], "accepted")

    def test_authenticated_recipient_refusal_stops_before_hub(self) -> None:
        _, result, raw, _ = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        directory = self.root_path / "provider-refusal"
        directory.mkdir(mode=0o700)
        inbox = OpaqueInbox(directory / "inbox.sqlite", clock=lambda: self.now)

        def refuse(_raw: bytes) -> None:
            raise ValueError("synthetic recipient policy refusal")

        ingress = TransportIngress(
            provider_ref="provider:refusal",
            route_ref="route:refusal",
            key_ref="credential:refusal",
            secret=self.secret,
            recipient_id="embodiment:daimonmatrix",
            recipient_body_ref="body:daimonmatrix",
            inbox=inbox,
            clock=lambda: self.now,
            intake_validator=refuse,
        )
        direct = self.provider("refusal", "direct", ingress.handle)
        hub_calls = 0

        class HubSpy:
            provider_ref = "provider:hub"
            route_ref = "route:hub"
            route_class = "hub"

            def inspect(self) -> Mapping[str, Any]:
                return {"available": True, "evidence_ref": "dm:evidence:v1:hub"}

            def manifest(self) -> Mapping[str, Any]:
                return _test_manifest(
                    self.provider_ref, self.route_ref, self.route_class
                )

            def deliver(self, _submission: Mapping[str, Any]) -> Mapping[str, Any]:
                nonlocal hub_calls
                hub_calls += 1
                return {}

        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [
                    self.binding(
                        "provider:refusal", "route:refusal", "direct", priority=0
                    ),
                    self.binding("provider:hub", "route:hub", "hub", priority=0),
                ]
            ),
            {direct.provider_ref: direct, "provider:hub": HubSpy()},
            clock=lambda: self.now,
        )
        dispatched = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        self.assertEqual(dispatched["status"], "refused")
        self.assertEqual(dispatched["selected"]["outcome"], "refused")
        self.assertEqual(hub_calls, 0)

    def test_ambiguous_direct_then_hub_and_retry_are_idempotent(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        direct_inbox, direct_ingress = self.ingress("direct", authorization)
        lost = True

        def response_loss(request: bytes) -> bytes:
            nonlocal lost
            response = direct_ingress.handle(request)
            if lost:
                lost = False
                raise ConnectionError("response lost after durable intake")
            return response

        direct = self.provider("direct", "direct", response_loss)
        hub_inbox, hub_ingress = self.ingress("hub", authorization, hub=True)
        hub = self.provider("hub", "hub", hub_ingress.handle)
        rows = [
            self.binding("provider:direct", "route:direct", "direct", priority=0),
            self.binding("provider:hub", "route:hub", "hub", priority=0),
        ]
        coordinator = RouteCoordinator(
            self.store,
            self.profile(rows),
            {direct.provider_ref: direct, hub.provider_ref: hub},
            clock=lambda: self.now,
        )
        first = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        self.assertEqual(first["selected"]["outcome"], "hub-accepted")
        second = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        self.assertEqual(second["selected"]["outcome"], "recipient-intake")
        claim = direct_inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:direct",
            claim_id=identifier(72_000_000, 3),
            limit=10,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(len(claim["items"]), 1)
        self.assertEqual(len(self.store.result(result["message_id"])["legs"]), 1)

        hub_claim = hub_inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:hub-forwarder",
            claim_id=identifier(72_000_000, 4),
            limit=10,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(len(hub_claim["items"]), 1)
        forward_ingress = TransportIngress(
            provider_ref="provider:forward",
            route_ref="route:forward",
            key_ref="credential:forward",
            secret=self.secret,
            recipient_id="embodiment:daimonmatrix",
            recipient_body_ref="body:daimonmatrix",
            inbox=direct_inbox,
            clock=lambda: self.now,
            intake_validator=self.validator(authorization),
        )
        forward = AuthenticatedProvider(
            provider_ref="provider:forward",
            route_ref="route:forward",
            route_class="direct",
            key_ref="credential:forward",
            secret=self.secret,
            sender_principal="hub-forwarder@remote",
            sender_body_ref="body:hub-forwarder",
            round_trip=forward_ingress.handle,
            clock=lambda: self.now,
        )
        forwarded_envelope = unb64url(hub_claim["items"][0]["envelope"])
        metadata = json.loads(forwarded_envelope)
        forwarded = forward.deliver(
            {
                "schema": "dm.route-submission/v1",
                "attempt_id": identifier(72_000_000, 5),
                "leg_id": leg_id,
                "message_id": result["message_id"],
                "recipient_id": "embodiment:daimonmatrix",
                "delivery_id": metadata["delivery_id"],
                "envelope_sha256": hashlib.sha256(forwarded_envelope).hexdigest(),
                "envelope": b64url(forwarded_envelope),
                "deadline_ms": NOW + 20_000,
            }
        )
        self.assertEqual(forwarded["outcome"], "recipient-intake")
        replay_claim = direct_inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:direct",
            claim_id=identifier(72_000_000, 3),
            limit=10,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(replay_claim, claim)

    def test_localhost_mixed_or_remote_scope_has_zero_provider_effect(self) -> None:
        _, result, raw, authorization = self.message_and_delivery(
            recipients=("legion", "daimonmatrix")
        )
        remote_leg = next(
            row
            for row in result["legs"]
            if row["recipient_id"] == "embodiment:daimonmatrix"
        )
        calls = 0
        _, ingress = self.ingress("direct", authorization)

        def counted(request: bytes) -> bytes:
            nonlocal calls
            calls += 1
            return ingress.handle(request)

        provider = AuthenticatedProvider(
            provider_ref="provider:direct",
            route_ref="route:direct",
            route_class="direct",
            key_ref="credential:direct",
            secret=self.secret,
            sender_principal="compaii@localhost",
            sender_body_ref="body:legion",
            round_trip=counted,
            clock=lambda: self.now,
        )
        profile = self.profile(
            [self.binding("provider:direct", "route:direct", "direct", priority=0)],
            principal_id="compaii@localhost",
            local_recipient_ids=["embodiment:legion"],
        )
        coordinator = RouteCoordinator(
            self.store,
            profile,
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(RouteError, "localhost_scope_refused"):
            coordinator.dispatch(
                leg_id=remote_leg["leg_id"],
                envelope=raw,
                deadline_ms=NOW + 20_000,
            )
        self.assertEqual(calls, 0)


class InboxAndProtocolTests(RouteFixture):
    def test_presence_and_fence_gate_must_be_complete_and_current(self) -> None:
        for presence_ref, fence_ref in (
            ("presence:stale", "fence:current"),
            ("presence:current", "fence:forked"),
            ("presence:substituted", "fence:current"),
        ):
            with self.subTest(presence_ref=presence_ref, fence_ref=fence_ref):
                _, result, raw, authorization = self.message_and_delivery()
                suffix = presence_ref.rsplit(":", 1)[-1] + fence_ref.rsplit(":", 1)[-1]
                directory = self.root_path / f"provider-gate-{suffix}"
                directory.mkdir(mode=0o700)
                inbox = OpaqueInbox(directory / "inbox.sqlite", clock=lambda: self.now)

                def require_current(presence: str, fence: str) -> None:
                    if presence != "presence:current" or fence != "fence:current":
                        raise RouteError("intake_gate_not_current")

                ingress = TransportIngress(
                    provider_ref=f"provider:{suffix}",
                    route_ref=f"route:{suffix}",
                    key_ref=f"credential:{suffix}",
                    secret=self.secret,
                    recipient_id="embodiment:daimonmatrix",
                    recipient_body_ref="body:daimonmatrix",
                    inbox=inbox,
                    clock=lambda: self.now,
                    presence_ref=presence_ref,
                    fence_ref=fence_ref,
                    intake_validator=self.validator(authorization),
                    intake_gate=require_current,
                )
                provider = self.provider(suffix, "direct", ingress.handle)
                coordinator = RouteCoordinator(
                    self.store,
                    self.profile(
                        [
                            self.binding(
                                f"provider:{suffix}",
                                f"route:{suffix}",
                                "direct",
                                priority=0,
                            )
                        ]
                    ),
                    {provider.provider_ref: provider},
                    clock=lambda: self.now,
                )
                refused = coordinator.dispatch(
                    leg_id=result["legs"][0]["leg_id"],
                    envelope=raw,
                    deadline_ms=NOW + 20_000,
                )
                self.assertEqual(refused["status"], "refused")

        _, _, _, authorization = self.message_and_delivery()
        directory = self.root_path / "provider-incomplete-gate"
        directory.mkdir(mode=0o700)
        with self.assertRaisesRegex(RouteError, "incomplete_intake_gate"):
            TransportIngress(
                provider_ref="provider:incomplete",
                route_ref="route:incomplete",
                key_ref="credential:incomplete",
                secret=self.secret,
                recipient_id="embodiment:daimonmatrix",
                recipient_body_ref="body:daimonmatrix",
                inbox=OpaqueInbox(directory / "inbox.sqlite", clock=lambda: self.now),
                clock=lambda: self.now,
                presence_ref="presence:current",
                fence_ref="fence:current",
                intake_validator=self.validator(authorization),
            )

    def test_direct_http_loopback_uses_authenticated_canonical_exchange(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, ingress = self.ingress("http", authorization)

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                size = int(self.headers["Content-Length"])
                response = ingress.handle(self.rfile.read(size))
                self.send_response(200)
                self.send_header("Content-Type", "application/daimon+jcs")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, _format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = cast(tuple[str, int], server.server_address)
            provider = DirectHTTPProvider(
                provider_ref="provider:http",
                route_ref="route:http",
                route_class="direct-anyvpn",
                key_ref="credential:http",
                secret=self.secret,
                sender_principal="compaii@remote",
                sender_body_ref="body:legion",
                endpoint=f"http://{host}:{port}/dm-route",
                clock=lambda: self.now,
            )
            coordinator = RouteCoordinator(
                self.store,
                self.profile(
                    [
                        self.binding(
                            "provider:http",
                            "route:http",
                            "direct-anyvpn",
                            priority=0,
                        )
                    ]
                ),
                {provider.provider_ref: provider},
                clock=lambda: self.now,
            )
            dispatched = coordinator.dispatch(
                leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
            )
            self.assertEqual(dispatched["selected"]["outcome"], "recipient-intake")
            self.assertNotIn(str(port).encode(), canonical_bytes(dispatched))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_local_unix_round_trip_is_authenticated_and_leak_free(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, ingress = self.ingress("local", authorization)
        socket_path = self.root_path / "route.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(socket_path))
        socket_path.chmod(0o600)
        listener.listen(1)

        def serve() -> None:
            connection, _ = listener.accept()
            with connection:
                serve_transport_connection(ingress, connection)
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        provider = LocalIPCProvider(
            provider_ref="provider:local",
            route_ref="route:local",
            route_class="local",
            key_ref="credential:local",
            secret=self.secret,
            sender_principal="compaii@remote",
            sender_body_ref="body:legion",
            socket_path=socket_path,
            clock=lambda: self.now,
        )
        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [
                    self.binding(
                        "provider:local",
                        "route:local",
                        "local",
                        priority=0,
                    )
                ]
            ),
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        dispatched = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        encoded = canonical_bytes(dispatched)
        self.assertNotIn(str(socket_path).encode(), encoded)
        self.assertNotIn(self.secret, encoded)

    def test_inbox_claims_are_stable_disjoint_and_compactable(self) -> None:
        _, _, raw, authorization = self.message_and_delivery()
        inbox, _ = self.ingress("bulk", authorization, hub=True)
        document = json.loads(raw)
        deliveries = []
        first_envelope = b""
        for index in range(106):
            changed = copy.deepcopy(document)
            changed["delivery_id"] = identifier(73_000_000, index)
            envelope = canonical_bytes(changed)
            if index == 0:
                first_envelope = envelope
            deliveries.append(
                (changed["delivery_id"], hashlib.sha256(envelope).hexdigest())
            )
            inbox.ingest(
                request_id=identifier(74_000_000, index),
                request_hash=hashlib.sha256(f"request:{index}".encode()).hexdigest(),
                recipient_id="embodiment:daimonmatrix",
                envelope=envelope,
            )
        first = inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:a",
            claim_id=identifier(75_000_000, 1),
            limit=100,
            lease_until_ms=NOW + 5_000,
        )
        replay = inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:a",
            claim_id=identifier(75_000_000, 1),
            limit=100,
            lease_until_ms=NOW + 5_000,
        )
        second = inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:b",
            claim_id=identifier(75_000_000, 2),
            limit=100,
            lease_until_ms=NOW + 5_000,
        )
        self.assertEqual(first, replay)
        self.assertEqual(len(first["items"]), 100)
        self.assertEqual(len(second["items"]), 6)
        self.assertTrue(
            {row["delivery_id"] for row in first["items"]}.isdisjoint(
                {row["delivery_id"] for row in second["items"]}
            )
        )
        with self.assertRaisesRegex(RouteError, "inbox_claim_not_owned"):
            inbox.ack(
                recipient_id="embodiment:daimonmatrix",
                consumer_id="consumer:a",
                delivery_id=second["items"][0]["delivery_id"],
                envelope_hash=second["items"][0]["envelope_sha256"],
            )
        for row in first["items"]:
            inbox.ack(
                recipient_id="embodiment:daimonmatrix",
                consumer_id="consumer:a",
                delivery_id=row["delivery_id"],
                envelope_hash=row["envelope_sha256"],
            )

        def reject_terminal(
            _recipient_id: str, _delivery_id: str, _envelope_hash: str
        ) -> None:
            raise RouteError("terminal_not_observed")

        with self.assertRaisesRegex(RouteError, "inbox_compaction_not_terminal"):
            inbox.compact(
                recipient_id="embodiment:daimonmatrix",
                through_sequence=100,
                terminal_validator=reject_terminal,
            )
        terminal_deliveries: list[str] = []

        def validate_terminal(
            recipient_id: str, delivery_id: str, envelope_hash: str
        ) -> None:
            self.assertEqual(recipient_id, "embodiment:daimonmatrix")
            self.assertEqual(
                dict(deliveries)[delivery_id],
                envelope_hash,
            )
            terminal_deliveries.append(delivery_id)

        compacted = inbox.compact(
            recipient_id="embodiment:daimonmatrix",
            through_sequence=100,
            terminal_validator=validate_terminal,
        )
        self.assertEqual(compacted["removed"], 100)
        self.assertEqual(len(terminal_deliveries), 100)
        self.assertEqual(len(deliveries), 106)
        tombstone_replay = inbox.ingest(
            request_id=identifier(74_000_000, 0),
            request_hash=hashlib.sha256(b"request:0").hexdigest(),
            recipient_id="embodiment:daimonmatrix",
            envelope=first_envelope,
        )
        self.assertTrue(tombstone_replay["replayed"])
        self.assertEqual(tombstone_replay["state"], "acked")
        self.assertEqual(tombstone_replay["sequence"], 1)

    def test_concurrent_inbox_claims_are_disjoint(self) -> None:
        _, _, raw, authorization = self.message_and_delivery()
        inbox, _ = self.ingress("concurrent", authorization, hub=True)
        document = json.loads(raw)
        for index in range(40):
            changed = copy.deepcopy(document)
            changed["delivery_id"] = identifier(79_000_000, index)
            envelope = canonical_bytes(changed)
            inbox.ingest(
                request_id=identifier(79_100_000, index),
                request_hash=hashlib.sha256(
                    f"concurrent-request:{index}".encode()
                ).hexdigest(),
                recipient_id="embodiment:daimonmatrix",
                envelope=envelope,
            )

        def claim(index: int) -> dict[str, Any]:
            return inbox.claim(
                recipient_id="embodiment:daimonmatrix",
                consumer_id=f"consumer:{index}",
                claim_id=identifier(79_200_000, index),
                limit=20,
                lease_until_ms=NOW + 5_000,
            )

        with ThreadPoolExecutor(max_workers=2) as workers:
            first, second = list(workers.map(claim, (1, 2)))
        first_ids = {row["delivery_id"] for row in first["items"]}
        second_ids = {row["delivery_id"] for row in second["items"]}
        self.assertEqual(len(first_ids), 20)
        self.assertEqual(len(second_ids), 20)
        self.assertTrue(first_ids.isdisjoint(second_ids))

    def test_inbox_restart_and_lease_expiry_reclaim_without_sequence_reset(
        self,
    ) -> None:
        _, _, raw, authorization = self.message_and_delivery()
        inbox, _ = self.ingress("restart", authorization, hub=True)
        inbox.ingest(
            request_id=identifier(79_300_000, 1),
            request_hash=hashlib.sha256(b"restart request").hexdigest(),
            recipient_id="embodiment:daimonmatrix",
            envelope=raw,
        )
        original = inbox.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:before-restart",
            claim_id=identifier(79_300_000, 2),
            limit=1,
            lease_until_ms=NOW + 100,
        )
        reopened = OpaqueInbox(inbox.path, clock=lambda: self.now)
        blocked = reopened.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:blocked",
            claim_id=identifier(79_300_000, 3),
            limit=1,
            lease_until_ms=NOW + 200,
        )
        self.assertEqual(blocked["items"], [])
        self.now = NOW + 100
        reclaimed = reopened.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:after-restart",
            claim_id=identifier(79_300_000, 4),
            limit=1,
            lease_until_ms=NOW + 300,
        )
        self.assertEqual(
            [row["sequence"] for row in reclaimed["items"]],
            [row["sequence"] for row in original["items"]],
        )
        replay = reopened.claim(
            recipient_id="embodiment:daimonmatrix",
            consumer_id="consumer:before-restart",
            claim_id=identifier(79_300_000, 2),
            limit=1,
            lease_until_ms=NOW + 100,
        )
        self.assertEqual(replay, original)

    def test_delivery_and_request_conflicts_fail_closed(self) -> None:
        _, _, raw, authorization = self.message_and_delivery()
        inbox, ingress = self.ingress("conflict", authorization, hub=True)
        metadata = json.loads(raw)
        request_id = identifier(76_000_000, 1)
        request_hash = hashlib.sha256(b"request one").hexdigest()
        inbox.ingest(
            request_id=request_id,
            request_hash=request_hash,
            recipient_id="embodiment:daimonmatrix",
            envelope=raw,
        )
        with self.assertRaisesRegex(RouteError, "transport_request_conflict"):
            inbox.ingest(
                request_id=request_id,
                request_hash="0" * 64,
                recipient_id="embodiment:daimonmatrix",
                envelope=raw,
            )
        changed = copy.deepcopy(metadata)
        changed["payload"]["ciphertext"] = "A" * len(changed["payload"]["ciphertext"])
        with self.assertRaisesRegex(RouteError, "delivery_id_conflict"):
            inbox.ingest(
                request_id=identifier(76_000_000, 2),
                request_hash=hashlib.sha256(b"request two").hexdigest(),
                recipient_id="embodiment:daimonmatrix",
                envelope=canonical_bytes(changed),
            )
        with self.assertRaisesRegex(RouteError, "intake_validator_required"):
            TransportIngress(
                provider_ref="provider:no-validator",
                route_ref="route:no-validator",
                key_ref="credential:no-validator",
                secret=self.secret,
                recipient_id="embodiment:daimonmatrix",
                recipient_body_ref="body:daimonmatrix",
                inbox=inbox,
                clock=lambda: self.now,
            )
        self.assertTrue(ingress.hub)


class ProviderNegativeTests(RouteFixture):
    def test_provider_status_outcome_and_intake_binding_are_coherent(self) -> None:
        _, result, raw, _ = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]

        class Incoherent:
            provider_ref = "provider:incoherent"
            route_ref = "route:incoherent"
            route_class = "direct"

            def inspect(self) -> Mapping[str, Any]:
                return {
                    "provider_ref": self.provider_ref,
                    "route_ref": self.route_ref,
                    "route_class": self.route_class,
                    "available": True,
                    "evidence_ref": "dm:evidence:v1:incoherent",
                }

            def manifest(self) -> Mapping[str, Any]:
                return _test_manifest(
                    self.provider_ref, self.route_ref, self.route_class
                )

            def deliver(self, submission: Mapping[str, Any]) -> Mapping[str, Any]:
                return {
                    "schema": PROVIDER_RESULT_SCHEMA,
                    "attempt_id": submission["attempt_id"],
                    "provider_ref": self.provider_ref,
                    "route_ref": self.route_ref,
                    "status": "accepted",
                    "outcome": "hub-accepted",
                    "evidence_ref": "dm:evidence:v1:incoherent",
                    "intake": None,
                }

        provider = Incoherent()
        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [
                    self.binding(
                        provider.provider_ref,
                        provider.route_ref,
                        provider.route_class,
                        priority=0,
                    )
                ]
            ),
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(RouteError, "invalid_provider_result"):
            coordinator.dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)

    def test_changed_bytes_under_delivery_id_quarantine_before_network(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, ingress = self.ingress("direct", authorization)
        calls = 0

        def counted(request: bytes) -> bytes:
            nonlocal calls
            calls += 1
            return ingress.handle(request)

        provider = self.provider("direct", "direct", counted)
        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [self.binding("provider:direct", "route:direct", "direct", priority=0)]
            ),
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        coordinator.dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)
        changed = json.loads(raw)
        changed["payload"]["ciphertext"] = "A" * len(changed["payload"]["ciphertext"])
        with self.assertRaisesRegex(CommunicationError, "delivery_id_conflict"):
            coordinator.dispatch(
                leg_id=leg_id,
                envelope=canonical_bytes(changed),
                deadline_ms=NOW + 20_000,
            )
        self.assertEqual(calls, 1)
        self.assertEqual(self.store.leg(leg_id)["state"], "quarantined")

    def test_tampered_authenticated_response_is_definitive_and_no_fallback(
        self,
    ) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, direct_ingress = self.ingress("direct", authorization)

        def tampered(request: bytes) -> bytes:
            response = json.loads(direct_ingress.handle(request))
            response["outcome"] = "hub-accepted"
            return canonical_bytes(response)

        direct = self.provider("direct", "direct", tampered)
        hub_calls = 0

        def hub_effect(_: Mapping[str, Any]) -> Mapping[str, Any]:
            nonlocal hub_calls
            hub_calls += 1
            return {}

        class HubSpy:
            provider_ref = "provider:hub"
            route_ref = "route:hub"
            route_class = "hub"

            def inspect(self) -> Mapping[str, Any]:
                return {"available": True, "evidence_ref": "dm:evidence:v1:hub"}

            def manifest(self) -> Mapping[str, Any]:
                return _test_manifest(
                    self.provider_ref, self.route_ref, self.route_class
                )

            def deliver(self, submission: Mapping[str, Any]) -> Mapping[str, Any]:
                return hub_effect(submission)

        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [
                    self.binding(
                        "provider:direct", "route:direct", "direct", priority=0
                    ),
                    self.binding("provider:hub", "route:hub", "hub", priority=0),
                ]
            ),
            {direct.provider_ref: direct, "provider:hub": HubSpy()},
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(RouteError, "transport_response_rejected"):
            coordinator.dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)
        self.assertEqual(hub_calls, 0)

    def test_provider_result_is_closed_and_cannot_supply_endpoint(self) -> None:
        _, result, raw, _ = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]

        class Malformed:
            provider_ref = "provider:bad"
            route_ref = "route:bad"
            route_class = "direct"

            def inspect(self) -> Mapping[str, Any]:
                return {"available": True, "evidence_ref": "dm:evidence:v1:bad"}

            def manifest(self) -> Mapping[str, Any]:
                return _test_manifest(
                    self.provider_ref, self.route_ref, self.route_class
                )

            def deliver(self, submission: Mapping[str, Any]) -> Mapping[str, Any]:
                return {
                    "schema": PROVIDER_RESULT_SCHEMA,
                    "attempt_id": submission["attempt_id"],
                    "provider_ref": self.provider_ref,
                    "route_ref": self.route_ref,
                    "status": "accepted",
                    "outcome": "recipient-intake",
                    "evidence_ref": "dm:evidence:v1:bad",
                    "intake": None,
                    "endpoint": "http://169.254.169.254/latest/meta-data",
                }

        coordinator = RouteCoordinator(
            self.store,
            self.profile(
                [self.binding("provider:bad", "route:bad", "direct", priority=0)]
            ),
            {"provider:bad": Malformed()},
            clock=lambda: self.now,
        )
        with self.assertRaisesRegex(RouteError, "invalid_provider_result"):
            coordinator.dispatch(leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000)


class HostedRouteBoundaryTests(RouteFixture):
    def test_authenticated_service_routes_only_with_explicit_profile(self) -> None:
        message, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, ingress = self.ingress("service", authorization)
        provider = self.provider("service", "direct", ingress.handle)
        router = RouteCoordinator(
            self.store,
            self.profile(
                [
                    self.binding(
                        "provider:service",
                        "route:service",
                        "direct",
                        priority=0,
                    )
                ]
            ),
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        capability = create_capability(
            hashlib.sha256(b"dm053 route capability").digest(),
            client_id="client:route-worker",
            methods=["route.inspect", "route.submit"],
            not_before_ms=NOW - 1_000,
            not_after_ms=NOW + 60_000,
        )
        service = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: self.now,
            communication=self.store,
            router=router,
        )
        inspect_request = create_request(
            capability,
            request_id=identifier(78_000_000, 1),
            issued_at_ms=self.now,
            method="route.inspect",
            params={"leg_id": leg_id},
            nonce=b"i" * 16,
        )
        inspected = service.handle(inspect_request)
        verify_response(
            inspected,
            capability,
            expected_request_id=inspect_request["request_id"],
            expected_request_hash=request_hash(inspect_request),
            expected_server=self.origins["legion"],
        )
        self.assertTrue(inspected["ok"])
        root_info = self.root_path.lstat()
        runtime = HostedRuntime(
            service,
            self.root_path,
            (root_info.st_dev, root_info.st_ino),
            self.root_path / "matrix.sock",
        )
        client, server = socket.socketpair()
        with client, server:
            client.sendall(encode_frame(inspect_request))
            serve_connection(runtime, server)
            daemon_response = decode_frame(client.recv(2 * 1024 * 1024))
        self.assertEqual(canonical_bytes(daemon_response), canonical_bytes(inspected))
        submit_request = create_request(
            capability,
            request_id=identifier(78_000_000, 2),
            issued_at_ms=self.now,
            method="route.submit",
            params={
                "leg_id": leg_id,
                "envelope": b64url(raw),
                "deadline_ms": NOW + 20_000,
            },
            nonce=b"s" * 16,
        )
        submitted = service.handle(submit_request)
        self.assertTrue(submitted["ok"])
        self.assertEqual(submitted["result"]["status"], "accepted")
        self.assertEqual(
            submitted["result"]["delivery_id"], json.loads(raw)["delivery_id"]
        )
        self.assertEqual(message["event_id"], result["message_id"])

        absent = HostedWeave(
            self.ledger_a,
            self.signers["legion"],
            {capability.capability_id: capability},
            lambda: self.now,
            communication=self.store,
        )
        refused_request = create_request(
            capability,
            request_id=identifier(78_000_000, 3),
            issued_at_ms=self.now,
            method="route.inspect",
            params={"leg_id": leg_id},
            nonce=b"r" * 16,
        )
        refused = absent.handle(refused_request)
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "route_profile_absent")


class RouteSchemaTests(RouteFixture):
    def test_runtime_documents_match_closed_schemas(self) -> None:
        _, result, raw, authorization = self.message_and_delivery()
        leg_id = result["legs"][0]["leg_id"]
        _, ingress = self.ingress("schema", authorization)
        exchange: list[dict[str, Any]] = []

        def capture(request: bytes) -> bytes:
            exchange.append(json.loads(request))
            response = ingress.handle(request)
            exchange.append(json.loads(response))
            return response

        provider = self.provider("schema", "direct", capture)
        profile = self.profile(
            [self.binding("provider:schema", "route:schema", "direct", priority=0)]
        )
        coordinator = RouteCoordinator(
            self.store,
            profile,
            {provider.provider_ref: provider},
            clock=lambda: self.now,
        )
        inspection = coordinator.inspect(leg_id=leg_id)
        dispatch = coordinator.dispatch(
            leg_id=leg_id, envelope=raw, deadline_ms=NOW + 20_000
        )
        schemas = {
            name: json.loads(
                (ROOT / "schemas" / "communication" / "v1" / name).read_bytes()
            )
            for name in (
                "gateway-edge.schema.json",
                "route-profile.schema.json",
                "route-provider.schema.json",
                "transport-request.schema.json",
            )
        }
        for schema in schemas.values():
            Draft202012Validator.check_schema(schema)

        def validator(name: str) -> Draft202012Validator:
            return Draft202012Validator(schemas[name], format_checker=FormatChecker())

        validator("route-profile.schema.json").validate(profile.public())
        route = validator("route-provider.schema.json")
        route.validate(provider.manifest())
        route.validate(inspection)
        route.validate(dispatch)
        route.validate(dispatch["selected"])
        transport = validator("transport-request.schema.json")
        for document in exchange:
            transport.validate(document)
        transport.validate(exchange[1]["intake"])
        fixture = json.loads(
            (
                ROOT / "conformance" / "fixtures" / "dm053-route-providers.json"
            ).read_bytes()
        )
        self.assertEqual(fixture["schema"], "dm.route.fixtures/v1")
        self.assertEqual(
            fixture["cases"], sorted(fixture["cases"], key=lambda row: row["id"])
        )


class GatewayBoundaryTests(unittest.TestCase):
    def policy(self, *, enabled: bool) -> GatewayPolicy:
        return GatewayPolicy.from_value(
            {
                "schema": GATEWAY_POLICY_SCHEMA,
                "gateway_ref": "gateway:synthetic",
                "enabled": enabled,
                "destinations": ["destination:ops"],
                "operations": ["message.mirror"],
                "classifications": ["shareable"],
                "source_scopes": ["scope:ops"],
                "max_chunk_bytes": 80,
            },
            authority_validator=(lambda _policy: None) if enabled else None,
        )

    def test_gateway_is_disabled_then_escaped_bounded_and_attributed(self) -> None:
        arguments = {
            "destination": "destination:ops",
            "operation": "message.mirror",
            "classification": "shareable",
            "source_scope": "scope:ops",
            "source_ref": "source:compaii",
            "message_id": identifier(77_000_000, 1),
            "text": "<b>not markup</b> " + "á" * 100,
        }
        with self.assertRaisesRegex(RouteError, "gateway_render_refused"):
            render_gateway(self.policy(enabled=False), **arguments)
        rendered = render_gateway(self.policy(enabled=True), **arguments)
        self.assertTrue(all(len(chunk.encode()) <= 80 for chunk in rendered["chunks"]))
        joined = "".join(rendered["chunks"])
        self.assertIn("&lt;b&gt;not markup&lt;/b&gt;", joined)
        self.assertIn(arguments["message_id"], joined)
        self.assertNotIn("<b>", joined)
        schema = json.loads(
            (
                ROOT / "schemas" / "communication" / "v1" / "gateway-edge.schema.json"
            ).read_bytes()
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(rendered)

    def test_gateway_allowlists_and_inbound_authority_fail_closed(self) -> None:
        with self.assertRaisesRegex(RouteError, "gateway_policy_authority_required"):
            GatewayPolicy.from_value(
                {
                    "schema": GATEWAY_POLICY_SCHEMA,
                    "gateway_ref": "gateway:synthetic",
                    "enabled": True,
                    "destinations": ["destination:ops"],
                    "operations": ["message.mirror"],
                    "classifications": ["shareable"],
                    "source_scopes": ["scope:ops"],
                    "max_chunk_bytes": 80,
                }
            )
        with self.assertRaisesRegex(RouteError, "gateway_render_refused"):
            render_gateway(
                self.policy(enabled=True),
                destination="destination:other",
                operation="message.mirror",
                classification="private",
                source_scope="scope:ops",
                source_ref="source:compaii",
                message_id=identifier(77_000_000, 2),
                text="secret",
            )
        proposal = gateway_proposal(
            gateway_ref="gateway:synthetic",
            destination="destination:ops",
            external_id="external:123",
            observed_at_ms=NOW,
            text="a human said this",
        )
        self.assertEqual(proposal["authority"], "external-source-only")
        self.assertNotIn("origin", proposal)
        self.assertNotIn("signature", proposal)


if __name__ == "__main__":
    unittest.main()
