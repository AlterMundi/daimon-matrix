"""Re-publication of a messaging application after a real manifest advance.

The advance here is not simulated: it enrolls one additional embodiment through
the same primitives the operator ceremony uses, so the epoch the published
application pins is genuinely a previous verified epoch of the same being rather
than a patched-in value.
"""

from __future__ import annotations

import copy
import json
import os
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.messaging_config import (
    MessagingConfigError,
    config_digest,
    load_application,
    read_document,
    read_publication,
)
from daimon_matrix.native_egress import closed_visibility
from daimon_matrix.operator_messaging import prepare, republish
from daimon_matrix.runtime import load_runtime
from daimon_matrix.synthetic_relationships import _seed
from tests.test_dm024_runtime import PASSWORD
from tests.test_messaging_runtime import application_fixture
from tests.test_operator_messaging import signed_visibility_installation


def _bundle_path(runtime: Any) -> Path:
    return Path(runtime.state_root) / "runtime.json"


def advance_manifest(runtime: Any) -> Any:
    """Enroll one additional embodiment for real and reload the runtime."""

    from daimon_matrix.operator_rebirth import (
        apply_activation_to_runtime_bundle,
        authority_from_runtime_bundle,
        authorize_enrollment_request,
        create_enrollment_request,
    )

    bundle = json.loads(_bundle_path(runtime).read_bytes())
    base = authority_from_runtime_bundle(bundle)
    now = runtime.service.clock()
    request = create_enrollment_request(
        base,
        signing_seed=_seed("republish:fresh-signing"),
        encryption_private=_seed("republish:fresh-encryption"),
        transport_seed=_seed("republish:fresh-transport"),
        body_ref="cluster:daimonmatrix:republish-fresh",
        embodiment_id="embodiment:republish:fresh",
        incarnation_id="incarnation:republish:fresh:0",
        principal_id="compaii@republish-fresh",
        created_at_ms=now + 10,
        expires_at_ms=now + 60_010,
        nonce=_seed("republish:fresh-request"),
    )
    activation = authorize_enrollment_request(
        request,
        base,
        # _identity() derives its root seeds deterministically and does not
        # expose them, so the ceremony's 2-of-3 quorum is reconstructed here
        # exactly as the synthetic genesis built it.
        root_seeds=tuple(_seed(f"founder:root:{index}") for index in range(3))[:2],
        issued_at_ms=now + 20,
    )
    advanced = apply_activation_to_runtime_bundle(
        bundle,
        activation,
        base,
        target_endpoint="http://127.0.0.1:45999/dm-peer/v1",
    )
    _bundle_path(runtime).write_bytes(canonical_bytes(advanced))
    clock = runtime.service.clock

    def password() -> bytearray:
        return bytearray(PASSWORD)

    return load_runtime(
        Path(runtime.state_root),
        "runtime.json",
        password,
        clock=clock,
        egress=closed_visibility(clock=clock, catalog_mode="migrate"),
    )


def daemon_visibility_check(runtime: Any, target: Path, installation: Path) -> None:
    """Run the exact check the daemon applies before it will serve a body.

    This is the boundary #186 owns: an application publication and its visibility
    installation are current-state documents, so a manifest advance makes the
    daemon refuse to start until both are re-issued against the present epoch.
    """

    from daimon_matrix.messaging_config import _read_publication
    from daimon_matrix.operator_messaging import (
        _application_authorities,
        _owner_visibility_controller,
        _runtime_authority,
    )

    application, _metadata = _read_publication(target, lambda _d, _b: None)
    _owner_visibility_controller(
        authorities=_application_authorities(application),
        application_sha256=config_digest(application),
        installation_path=installation,
        authority=_runtime_authority(runtime),
        origin=runtime.service.origin,
        runtime_id=runtime.service.runtime_id,
        runtime_label=runtime.service.runtime_label,
        signer_public_key=runtime.service.signer.public_key,
        clock=runtime.service.clock,
        catalog_mode="validate",
    )


def _generations(target: Path) -> list[str]:
    return sorted(path.name for path in target.iterdir() if path.is_dir())


class RepublishAfterAdvanceTests(unittest.TestCase):
    def published(
        self, *, max_ttl_ms: int | None = None
    ) -> tuple[Any, Path, Path, dict[str, Any], dict[str, bytes]]:
        runtime, spec, sources, _ = application_fixture(self)
        if max_ttl_ms is not None:
            from dataclasses import replace

            self.pair.policy = replace(self.pair.policy, max_ttl_ms=max_ttl_ms)
            self.pair.sender_context.policy = self.pair.receiver.policy = (
                self.pair.policy
            )
            spec["outgoing"]["policy"]["max_ttl_ms"] = max_ttl_ms
        target = self.root / "app"
        prepare(runtime, target, spec, secret_sources=sources)
        installation = signed_visibility_installation(
            self.root, runtime, self.pair, target
        )
        application, _metadata = read_publication(runtime, target)
        stores = {
            name: (target / name).read_bytes() for name in spec["stores"].values()
        }
        return runtime, target, installation, application, stores

    def retained_send(self, *, lose_message_response: bool = False):
        from dataclasses import replace

        from daimon_matrix.native_egress import synthetic_visibility
        from daimon_matrix.routes import OpaqueInbox, TransportIngress
        from daimon_matrix.synthetic_relationships import _uuid

        runtime, target, installation, application, _ = self.published(max_ttl_ms=1_000)
        loaded = load_application(runtime, target)
        delivery = loaded.service.messaging.deliveries["peer-out"]
        calls = []
        receiver_egress = synthetic_visibility(clock=lambda: self.pair.now)
        for phase, provider in zip(
            ("evidence", "message"), delivery.providers, strict=True
        ):
            route = application["outgoing"]["routes"][phase]
            ingress = TransportIngress(
                **{key: route[key] for key in ("provider_ref", "route_ref", "key_ref")},
                secret=(target / route["secret_file"]).read_bytes(),
                recipient_id=self.pair.policy.recipient_id,
                recipient_body_ref=self.pair.recipient.origin["body_ref"],
                recipient_embodiment_id=self.pair.recipient.origin["embodiment_id"],
                inbox=OpaqueInbox(
                    self.root / ("history-" + phase + ".sqlite"),
                    clock=lambda: self.pair.now,
                ),
                clock=lambda: self.pair.now,
                egress=receiver_egress,
                egress_catalog_id="history-" + phase,
                intake_validator=getattr(self.pair.receiver, "receive_" + phase),
            )

            def exchange(raw, phase=phase, ingress=ingress):
                calls.append((phase, raw))
                response = bytes(ingress.handle(raw))
                if lose_message_response and phase == "message":
                    raise ConnectionError("synthetic lost return after intake")
                return response

            provider._round_trip = exchange
        arguments = dict(
            client_id=application["client"]["descriptor"]["client_id"],
            send_id=_uuid("history-send"),
            thread_id=_uuid("history-thread"),
            text="Retained delivery proof",
        )
        result = delivery.send(**arguments)
        self.assertEqual(
            result["transport_status"],
            "pending" if lose_message_response else "recipient-intake",
        )
        advanced = advance_manifest(runtime)
        # Preserve this fixture's qualified echo proof key and destination. The
        # receive-only controller used by advance_manifest cannot verify these
        # already-authenticated synthetic transport/echo records.
        advanced = replace(
            advanced, egress=synthetic_visibility(clock=lambda: self.pair.now)
        )
        republish(advanced, target, installation=installation)
        selected = load_application(advanced, target).service.messaging.deliveries[
            "peer-out"
        ]
        for provider in selected.providers:
            provider._round_trip = lambda raw: self.fail(
                "historical inspection transmitted"
            )
        return advanced, target, selected, arguments, calls

    def test_historical_delivery_survives_actual_authority_advance_without_replay(self):
        for pending in (False, True):
            with self.subTest(pending=pending):
                _runtime, target, delivery, arguments, calls = self.retained_send(
                    lose_message_response=pending
                )
                self.pair.now += delivery.sender.context.policy.max_ttl_ms + 1
                delivery.sender.prepare = lambda **kwargs: self.fail(
                    "historical inspection prepared or renewed a carrier"
                )
                before = {
                    path.relative_to(target): path.read_bytes()
                    for path in target.rglob("*")
                    if path.is_file()
                }
                events = delivery.sender.ledger.events()
                result = delivery.inspect(
                    client_id=arguments["client_id"], send_id=arguments["send_id"]
                )
                self.assertEqual(
                    result["transport_status"],
                    "pending" if pending else "recipient-intake",
                )
                self.assertFalse(result["retryable"])
                self.assertEqual(
                    result["recovery"]["action"], "historical-inspection-only"
                )
                self.assertEqual(len(calls), 2)
                self.assertEqual(events, delivery.sender.ledger.events())
                self.assertEqual(
                    before,
                    {
                        path.relative_to(target): path.read_bytes()
                        for path in target.rglob("*")
                        if path.is_file()
                    },
                )

    def test_historical_delivery_refuses_missing_or_forged_provenance(self):
        _runtime, target, delivery, arguments, _calls = self.retained_send()
        binding = target / "binding.json"
        original = binding.read_bytes()
        binding.unlink()
        with self.assertRaises(ValueError):
            delivery.inspect(
                client_id=arguments["client_id"], send_id=arguments["send_id"]
            )
        forged = json.loads(original)
        forged["signature"] = "A" * len(forged["signature"])
        binding.write_bytes(canonical_bytes(forged))
        with self.assertRaises(ValueError):
            delivery.inspect(
                client_id=arguments["client_id"], send_id=arguments["send_id"]
            )

    def test_historical_configuration_refuses_signed_context_substitutions(self):
        from daimon_matrix.messaging_config import (
            _transport_config_digest,
            _verify_historical_transport,
            create_binding,
        )

        runtime, target, _delivery, _arguments, _calls = self.retained_send()
        current, metadata = read_publication(runtime, target)
        retained_digest = _transport_config_digest(
            read_document(target / "application.json")
        )
        publication = read_document(target / "publication.json")
        for field in (
            "endpoint",
            "provider_ref",
            "route_ref",
            "key_ref",
            "secret_sha256",
            "policy",
            "stores",
            "foreign",
            "history",
            "schema",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(current)
                route = changed["outgoing"]["routes"]["message"]
                if field == "policy":
                    changed["outgoing"]["policy"]["max_ttl_ms"] -= 1
                elif field == "stores":
                    changed["stores"]["inbox"] = "different.sqlite"
                elif field == "foreign":
                    changed["authorities"].reverse()
                elif field == "history":
                    changed["relationship_events"] = changed["relationship_events"][:-1]
                elif field == "schema":
                    changed["schema"] = "dm.messaging.application/v2"
                elif field == "endpoint":
                    route[field] = "http://127.0.0.1:45201/dm-messaging/v1/message"
                elif field == "secret_sha256":
                    route[field] = "f" * 64
                else:
                    route[field] = "different:" + field
                (metadata / "application.json").write_bytes(canonical_bytes(changed))
                (metadata / "binding.json").write_bytes(
                    canonical_bytes(create_binding(runtime, changed))
                )
                body = {
                    **publication["body"],
                    "application_sha256": config_digest(changed),
                }
                (target / "publication.json").write_bytes(
                    canonical_bytes(
                        dict(body=body, binding=create_binding(runtime, body))
                    )
                )
                with self.assertRaisesRegex(ValueError, "messaging_transport_conflict"):
                    _verify_historical_transport(
                        runtime, target, changed, retained_digest
                    )

    def test_historical_inspection_rechecks_current_publication_before_return(self):
        from daimon_matrix.messaging_config import create_binding

        runtime, target, delivery, arguments, _calls = self.retained_send()
        current, metadata = read_publication(runtime, target)
        publication = read_document(target / "publication.json")
        provider = delivery.providers[0]
        verify = provider.validate_prepared_response

        def replace_publication(request, response):
            result = verify(request, response)
            current["outgoing"]["routes"]["message"]["endpoint"] = (
                "http://127.0.0.1:45201/dm-messaging/v1/message"
            )
            (metadata / "application.json").write_bytes(canonical_bytes(current))
            (metadata / "binding.json").write_bytes(
                canonical_bytes(create_binding(runtime, current))
            )
            body = {**publication["body"], "application_sha256": config_digest(current)}
            (target / "publication.json").write_bytes(
                canonical_bytes(dict(body=body, binding=create_binding(runtime, body)))
            )
            return result

        provider.validate_prepared_response = replace_publication
        with self.assertRaisesRegex(ValueError, "messaging_transport_conflict"):
            delivery.inspect(
                client_id=arguments["client_id"], send_id=arguments["send_id"]
            )

    def test_historical_inspection_refuses_mixed_phase_selections(self):
        import sqlite3
        from contextlib import closing

        _runtime, _target, delivery, arguments, _calls = self.retained_send()
        with closing(sqlite3.connect(delivery.sender.outbox.path)) as database:
            encoded = database.execute(
                "SELECT binding FROM messaging_transport_stages WHERE phase='evidence'"
            ).fetchone()[0]
            binding = json.loads(encoded)
            binding["config_digest"] = delivery.config_digest
            database.execute(
                "UPDATE messaging_transport_stages SET binding=? "
                "WHERE phase='evidence'",
                (canonical_bytes(binding),),
            )
            database.commit()
        before = delivery.sender.outbox.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "messaging_transport_conflict"):
            delivery.inspect(
                client_id=arguments["client_id"], send_id=arguments["send_id"]
            )
        self.assertEqual(before, delivery.sender.outbox.path.read_bytes())

    def test_advance_strands_the_application_and_republish_repairs_it(self) -> None:
        runtime, target, installation, previous, stores = self.published()
        # The application loads at the epoch it was published under.
        self.assertIsNotNone(load_application(runtime, target).service.messaging)

        advanced_runtime = advance_manifest(runtime)
        self.assertEqual(
            advanced_runtime.service.ledger.authority.manifest.value["revision"],
            runtime.service.ledger.authority.manifest.value["revision"] + 1,
        )
        # This is the reported defect: the publication no longer verifies, so no
        # verb that starts from a verified publication can repair it, and the
        # daemon refuses to start the body.
        with self.assertRaises(MessagingConfigError):
            read_publication(advanced_runtime, target)
        with self.assertRaises(MessagingConfigError):
            daemon_visibility_check(advanced_runtime, target, installation)

        receipt = republish(
            advanced_runtime,
            target,
            installation=installation,
            bundle_name="runtime.json",
        )
        self.assertEqual(receipt["status"], "republished")
        self.assertEqual(
            receipt["previous_application_sha256"], config_digest(previous)
        )
        self.assertNotEqual(
            receipt["application_sha256"], receipt["previous_application_sha256"]
        )
        self.assertTrue(receipt["installation"]["reissued"])

        successor, metadata = read_publication(advanced_runtime, target)
        self.assertEqual(metadata.name, receipt["generation"])
        self.assertEqual(config_digest(successor), receipt["application_sha256"])
        # The daemon's own check refused this body before the repair and accepts
        # it afterwards, which is the failure the owner-visible symptom named.
        daemon_visibility_check(advanced_runtime, target, installation)

        # Exactly one field of the application moved: this being's authority entry.
        being_ref = advanced_runtime.service.ledger.authority.manifest.being_ref
        changed = [
            index
            for index, (before, after) in enumerate(
                zip(previous["authorities"], successor["authorities"], strict=True)
            )
            if before != after
        ]
        self.assertEqual(len(changed), 1)
        self.assertEqual(
            successor["authorities"][changed[0]]["manifest"]["being_ref"], being_ref
        )
        self.assertEqual(
            successor["authorities"][changed[0]]["manifest"]["revision"],
            advanced_runtime.service.ledger.authority.manifest.value["revision"],
        )
        restored = copy.deepcopy(successor)
        restored["authorities"] = previous["authorities"]
        self.assertEqual(restored, previous)
        self.assertEqual(set(previous), set(successor))

        # Nothing security-bearing was rotated, re-minted or rewritten.
        self.assertEqual(
            stores,
            {name: (target / name).read_bytes() for name in stores},
        )
        self.assertEqual(
            successor["client"]["descriptor"], previous["client"]["descriptor"]
        )
        self.assertEqual(
            read_document(metadata / "client.json"),
            read_document(target / "client.json"),
        )
        self.assertEqual(
            (target / previous["client"]["secret_file"]).read_bytes(),
            (target / successor["client"]["secret_file"]).read_bytes(),
        )

    def test_foreign_acceptance_is_preserved_byte_identically(self) -> None:
        runtime, target, installation, _previous, _stores = self.published()
        before = read_document(installation)
        advanced_runtime = advance_manifest(runtime)
        receipt = republish(advanced_runtime, target, installation=installation)
        after = read_document(installation)

        being_ref = advanced_runtime.service.ledger.authority.manifest.being_ref
        participants = before["document"]["disclosure"]["participants"]
        owner_index = participants.index(being_ref)

        # The disclosure nobody re-consented to is untouched, so the digest every
        # foreign acceptance was issued over is untouched.
        self.assertEqual(
            after["document"]["disclosure"], before["document"]["disclosure"]
        )
        self.assertEqual(
            after["document"]["acceptance_set"]["disclosure_sha256"],
            before["document"]["acceptance_set"]["disclosure_sha256"],
        )
        foreign_before = [
            row
            for i, row in enumerate(before["document"]["acceptance_set"]["bindings"])
            if i != owner_index
        ]
        foreign_after = [
            row
            for i, row in enumerate(after["document"]["acceptance_set"]["bindings"])
            if i != owner_index
        ]
        self.assertEqual(foreign_after, foreign_before)
        self.assertTrue(foreign_after, "the fixture must have a foreign acceptance")
        # Only the owner's own attestation moved, and the generation advanced.
        self.assertNotEqual(
            after["document"]["acceptance_set"]["bindings"][owner_index],
            before["document"]["acceptance_set"]["bindings"][owner_index],
        )
        self.assertEqual(
            after["document"]["generation"], before["document"]["generation"] + 1
        )
        self.assertEqual(
            after["document"]["policy"]["generation"], after["document"]["generation"]
        )
        for unchanged in ("schema", "runtime_id", "secrets", "telegram_qualification"):
            self.assertEqual(
                after["document"][unchanged], before["document"][unchanged]
            )
        self.assertEqual(
            after["document"]["application_sha256"], receipt["application_sha256"]
        )
        # The replaced installation is retained so the whole operation is reversible.
        backup = (
            installation.parent
            / receipt["installation"]["previous_installation_backup"]
        )
        self.assertEqual(read_document(backup), before)

    def test_republish_is_idempotent_and_appends_nothing(self) -> None:
        runtime, target, installation, _previous, _stores = self.published()
        advanced_runtime = advance_manifest(runtime)
        first = republish(advanced_runtime, target, installation=installation)
        generations = _generations(target)
        installation_bytes = installation.read_bytes()

        second = republish(advanced_runtime, target, installation=installation)
        self.assertEqual(second["status"], "current")
        self.assertEqual(second["application_sha256"], first["application_sha256"])
        self.assertFalse(second["installation"]["reissued"])
        self.assertEqual(_generations(target), generations)
        self.assertEqual(installation.read_bytes(), installation_bytes)
        self.assertEqual(
            read_document(target / "publication.json")["body"]["generation"],
            first["generation"],
        )

    def test_unauthentic_predecessor_is_refused_without_mutation(self) -> None:
        runtime, target, installation, previous, _stores = self.published()
        advanced_runtime = advance_manifest(runtime)
        predecessor = config_digest(previous)
        generations = _generations(target)
        installation_bytes = installation.read_bytes()

        # A file on disk is not a predecessor: re-sign the same bytes under a key
        # that never belonged to this embodiment.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from daimon_matrix.canonical import b64url
        from daimon_matrix.messaging_config import BINDING_DOMAIN, _public_identity

        forged_body = {
            **_public_identity(
                advanced_runtime.service.ledger.authority,
                advanced_runtime.service.origin,
                advanced_runtime.service.runtime_id,
                advanced_runtime.service.runtime_label,
                advanced_runtime.service.clock(),
            ),
            "application_sha256": predecessor,
        }
        forged = {
            "schema": "dm.messaging.operator-binding/v1",
            "body": forged_body,
            "signature": b64url(
                Ed25519PrivateKey.from_private_bytes(_seed("republish:forged")).sign(
                    BINDING_DOMAIN + canonical_bytes(forged_body)
                )
            ),
        }
        (target / "binding.json").write_bytes(canonical_bytes(forged))
        # Snapshot after the tampering, so the only permitted difference is the
        # file the attacker wrote: nothing this operation owns may move.
        before = {
            path.name: path.read_bytes() for path in target.iterdir() if path.is_file()
        }
        with self.assertRaises(MessagingConfigError):
            republish(advanced_runtime, target, installation=installation)

        self.assertEqual(
            before,
            {
                path.name: path.read_bytes()
                for path in target.iterdir()
                if path.is_file()
            },
        )
        self.assertEqual(_generations(target), generations)
        self.assertEqual(installation.read_bytes(), installation_bytes)
        self.assertEqual(
            read_document(target / "publication.json")["body"]["application_sha256"],
            predecessor,
        )

    def test_interrupted_publication_leaves_an_unselected_candidate(self) -> None:
        runtime, target, installation, previous, _stores = self.published()
        advanced_runtime = advance_manifest(runtime)
        predecessor = config_digest(previous)
        generations = _generations(target)
        real_replace = os.replace

        def refuse(source: Any, destination: Any) -> None:
            if str(destination).endswith("publication.json"):
                raise OSError("simulated crash before the sole visibility transition")
            real_replace(source, destination)

        with (
            patch("daimon_matrix.operator_messaging.os.replace", side_effect=refuse),
            self.assertRaises(MessagingConfigError),
        ):
            republish(advanced_runtime, target, installation=installation)

        # The pointer never moved, so the predecessor is still what is published.
        self.assertEqual(
            read_document(target / "publication.json")["body"]["application_sha256"],
            predecessor,
        )
        candidates = [name for name in _generations(target) if name not in generations]
        # A failed candidate generation is retained for diagnosis and never selected.
        self.assertEqual(len(candidates), 1)
        self.assertTrue((target / candidates[0] / "application.json").is_file())
        self.assertEqual(
            read_document(target / "publication.json")["body"]["generation"], "."
        )

        # The retry converges from the interrupted state.
        receipt = republish(advanced_runtime, target, installation=installation)
        self.assertEqual(receipt["status"], "republished")
        successor, metadata = read_publication(advanced_runtime, target)
        self.assertEqual(metadata.name, receipt["generation"])
        self.assertNotEqual(metadata.name, candidates[0])
        self.assertEqual(config_digest(successor), receipt["application_sha256"])
        daemon_visibility_check(advanced_runtime, target, installation)


if __name__ == "__main__":
    unittest.main()
