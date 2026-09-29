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
    def published(self) -> tuple[Any, Path, Path, dict[str, Any], dict[str, bytes]]:
        runtime, spec, sources, _ = application_fixture(self)
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
