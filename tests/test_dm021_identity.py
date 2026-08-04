from __future__ import annotations

import copy
import hashlib
import json
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from daimon_matrix.canonical import CanonicalError, canonical_bytes, unb64url
from daimon_matrix.identity import (
    ControlChain,
    ControlForkError,
    VerificationError,
    create_binding_activation,
    create_embodiment_credential,
    create_genesis,
    create_history_binding,
    create_incarnation_authorization,
    create_recovery,
    create_revocation,
    create_root_rotation,
    ed25519_public,
    key_descriptor,
    require_trust_mode,
    verify_binding_activation,
    verify_embodiment_credential,
    verify_genesis,
    verify_history_binding,
    verify_incarnation_authorization,
    verify_recovery,
    verify_successor,
    x25519_public,
)

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000_000


def seed(label: str) -> bytes:
    return hashlib.sha256(f"dm-021-test:{label}".encode()).digest()


def transport(label: str, principal_id: str) -> dict[str, Any]:
    return {
        "key": key_descriptor("Ed25519", ed25519_public(seed(label))),
        "principal_id": principal_id,
        "scheme": "tribe-v1",
    }


class IdentityFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.root = [seed("root-a"), seed("root-b"), seed("root-c")]
        self.recovery = [
            seed("recovery-a"),
            seed("recovery-b"),
            seed("recovery-c"),
        ]
        self.genesis = create_genesis(
            self.root,
            2,
            self.recovery,
            2,
            created_at_ms=NOW,
            nonce=seed("being-nonce"),
        )
        self.state = verify_genesis(self.genesis)

    def credential(
        self,
        label: str,
        *,
        root: list[bytes] | None = None,
        state: Any | None = None,
    ) -> dict[str, Any]:
        selected_state = self.state if state is None else state
        return create_embodiment_credential(
            selected_state,
            self.root if root is None else root,
            seed(f"{label}-signing"),
            x25519_public(seed(f"{label}-encryption")),
            embodiment_id=f"embodiment:{label}",
            body_ref=f"cluster:{label}:body",
            purposes=["dm.we", "messages"],
            valid_from_ms=NOW - 100,
            valid_until_ms=NOW + 100_000,
            transport_principals=[transport(f"{label}-tribe", f"compaii@{label}")],
        )


class CanonicalizationTests(unittest.TestCase):
    def test_object_keys_use_jcs_utf16_order(self) -> None:
        value = {"\ue000": 1, "😀": 2}
        self.assertEqual(canonical_bytes(value), '{"😀":2,"\ue000":1}'.encode())

    def test_non_nfc_float_and_unsafe_integer_are_rejected(self) -> None:
        for value in ({"text": "e\u0301"}, {"number": 1.5}, {"number": 2**53}):
            with self.subTest(value=value), self.assertRaises(CanonicalError):
                canonical_bytes(value)


class PluralAuthorizationTests(IdentityFixture):
    def test_two_embodiments_are_valid_concurrently(self) -> None:
        first = self.credential("legion")
        second = self.credential("daimonmatrix")

        first_body = verify_embodiment_credential(first, self.state, at_ms=NOW)
        second_body = verify_embodiment_credential(second, self.state, at_ms=NOW)

        self.assertNotEqual(first_body["embodiment_id"], second_body["embodiment_id"])
        self.assertEqual(
            first_body["being_ref"],
            second_body["being_ref"],
        )
        self.assertEqual(
            first_body["transport_principals"][0]["principal_id"],
            "compaii@legion",
        )

    def test_body_key_and_principal_substitution_fail_closed(self) -> None:
        credential = self.credential("legion")
        mutations: list[Callable[[dict[str, Any]], None]] = [
            lambda value: value["body"].update(body_ref="cluster:other:body"),
            lambda value: value["body"].update(
                signing_key=key_descriptor(
                    "Ed25519", ed25519_public(seed("substitute-signing"))
                )
            ),
            lambda value: value["body"]["transport_principals"][0].update(
                principal_id="compaii@attacker"
            ),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(credential)
                mutate(changed)
                with self.assertRaises(VerificationError):
                    verify_embodiment_credential(changed, self.state, at_ms=NOW)

    def test_root_recovery_and_embodiment_keys_are_purpose_separated(self) -> None:
        with self.assertRaises(VerificationError):
            create_genesis(
                self.root,
                2,
                [self.root[0], seed("other-rec-a"), seed("other-rec-b")],
                2,
                created_at_ms=NOW,
            )

        aliased = create_embodiment_credential(
            self.state,
            self.root,
            self.root[0],
            x25519_public(seed("alias-encryption")),
            embodiment_id="embodiment:alias",
            body_ref="cluster:alias:body",
            purposes=["messages"],
            valid_from_ms=NOW - 1,
            valid_until_ms=NOW + 1,
        )
        with self.assertRaises(VerificationError):
            verify_embodiment_credential(aliased, self.state, at_ms=NOW)

        encryption_alias = create_embodiment_credential(
            self.state,
            self.root,
            seed("encryption-alias-signing"),
            ed25519_public(self.root[0]),
            embodiment_id="embodiment:encryption-alias",
            body_ref="cluster:encryption-alias:body",
            purposes=["messages"],
            valid_from_ms=NOW - 1,
            valid_until_ms=NOW + 1,
        )
        with self.assertRaises(VerificationError):
            verify_embodiment_credential(encryption_alias, self.state, at_ms=NOW)


class IncarnationAndRevocationTests(IdentityFixture):
    def test_restart_changes_incarnation_not_embodiment(self) -> None:
        credential = self.credential("legion")
        first = create_incarnation_authorization(
            credential,
            seed("legion-signing"),
            incarnation_id="incarnation:legion:0",
            incarnation_sequence=0,
            started_at_ms=NOW,
        )
        restarted = create_incarnation_authorization(
            credential,
            seed("legion-signing"),
            incarnation_id="incarnation:legion:1",
            incarnation_sequence=1,
            started_at_ms=NOW + 1,
        )

        first_body = verify_incarnation_authorization(
            first, credential, self.state, at_ms=NOW
        )
        restarted_body = verify_incarnation_authorization(
            restarted, credential, self.state, at_ms=NOW + 1
        )
        self.assertEqual(first_body["embodiment_id"], restarted_body["embodiment_id"])
        self.assertNotEqual(
            first_body["incarnation_id"], restarted_body["incarnation_id"]
        )

    def test_revocation_preserves_history_and_does_not_revoke_peer(self) -> None:
        first = self.credential("legion")
        peer = self.credential("daimonmatrix")
        historical = create_incarnation_authorization(
            first,
            seed("legion-signing"),
            incarnation_id="incarnation:legion:0",
            incarnation_sequence=0,
            started_at_ms=NOW,
        )
        later = create_incarnation_authorization(
            first,
            seed("legion-signing"),
            incarnation_id="incarnation:legion:1",
            incarnation_sequence=1,
            started_at_ms=NOW + 1,
        )
        revocation = create_revocation(
            self.state,
            self.root,
            embodiment_id="embodiment:legion",
            cutoff_incarnation_sequence=0,
            revocation_generation=1,
        )
        revoked_state = verify_successor(revocation, self.state)

        verify_incarnation_authorization(historical, first, revoked_state, at_ms=NOW)
        with self.assertRaises(VerificationError):
            verify_incarnation_authorization(later, first, revoked_state, at_ms=NOW + 1)
        with self.assertRaises(VerificationError):
            verify_embodiment_credential(first, revoked_state, at_ms=NOW)
        verify_embodiment_credential(peer, revoked_state, at_ms=NOW)


class RotationAndRecoveryTests(IdentityFixture):
    def test_rotation_requires_both_thresholds_and_explicit_carry_forward(self) -> None:
        carried = self.credential("legion")
        dropped = self.credential("daimonmatrix")
        replacement = [seed("new-root-a"), seed("new-root-b"), seed("new-root-c")]
        rotation = create_root_rotation(
            self.state,
            self.root,
            replacement,
            2,
            carry_forward_credentials=[carried["artifact_id"]],
        )

        partial_old = copy.deepcopy(rotation)
        kept_one = False
        filtered = []
        for signature in partial_old["signatures"]:
            if signature["role"] == "root-authorization":
                if kept_one:
                    continue
                kept_one = True
            filtered.append(signature)
        partial_old["signatures"] = filtered
        with self.assertRaises(VerificationError):
            verify_successor(partial_old, self.state)

        rotated = verify_successor(rotation, self.state)
        verify_embodiment_credential(carried, rotated, at_ms=NOW)
        with self.assertRaises(VerificationError):
            verify_embodiment_credential(dropped, rotated, at_ms=NOW)

        chain = ControlChain(self.genesis)
        chain.add(rotation)
        with self.assertRaisesRegex(VerificationError, "replay"):
            chain.add(rotation)

    def test_competing_successors_quarantine_until_recovery_names_every_head(
        self,
    ) -> None:
        root_a = [seed("branch-a-1"), seed("branch-a-2"), seed("branch-a-3")]
        root_b = [seed("branch-b-1"), seed("branch-b-2"), seed("branch-b-3")]
        first = create_root_rotation(self.state, self.root, root_a, 2)
        second = create_root_rotation(self.state, self.root, root_b, 2)
        chain = ControlChain(self.genesis)
        chain.add(first)
        chain.add(second)

        with self.assertRaises(ControlForkError):
            _ = chain.state

        incomplete_root = [seed("incomplete-1"), seed("incomplete-2")]
        incomplete = create_recovery(
            [chain.states()[0]],
            self.recovery,
            incomplete_root,
            2,
            revoke_embodiments=[],
        )
        with self.assertRaises(VerificationError):
            chain.add(incomplete)

        recovered_root = [seed("recovered-1"), seed("recovered-2")]
        recovery = create_recovery(
            chain.states(),
            self.recovery,
            recovered_root,
            2,
            revoke_embodiments=["embodiment:compromised"],
        )
        recovered = chain.add(recovery)
        self.assertEqual(chain.state, recovered)
        self.assertEqual(recovered.generation, 1)
        self.assertEqual(recovered.sequence, 0)
        self.assertEqual(len(chain.heads), 1)

    def test_loss_of_both_thresholds_cannot_recreate_the_being(self) -> None:
        replacement = [seed("lost-replacement-a"), seed("lost-replacement-b")]
        unauthorized = create_recovery(
            [self.state],
            [],
            replacement,
            2,
            revoke_embodiments=[],
        )
        with self.assertRaises(VerificationError):
            verify_recovery(unauthorized, [self.state])

        successor = create_genesis(
            replacement,
            2,
            [seed("successor-rec-a"), seed("successor-rec-b")],
            2,
            created_at_ms=NOW + 1,
            nonce=seed("successor-being-nonce"),
        )
        successor_state = verify_genesis(successor)
        self.assertNotEqual(successor_state.being_ref, self.state.being_ref)
        with self.assertRaises(VerificationError):
            verify_embodiment_credential(
                self.credential("legion"), successor_state, at_ms=NOW
            )

    def test_recovery_conservatively_merges_every_branch_revocation(self) -> None:
        legion_wide = verify_successor(
            create_revocation(
                self.state,
                self.root,
                embodiment_id="embodiment:legion",
                cutoff_incarnation_sequence=3,
                revocation_generation=1,
            ),
            self.state,
        )
        legion_strict = verify_successor(
            create_revocation(
                self.state,
                self.root,
                embodiment_id="embodiment:legion",
                cutoff_incarnation_sequence=1,
                revocation_generation=1,
            ),
            self.state,
        )
        peer_state = verify_successor(
            create_revocation(
                legion_strict,
                self.root,
                embodiment_id="embodiment:daimonmatrix",
                cutoff_incarnation_sequence=4,
                revocation_generation=1,
            ),
            legion_strict,
        )
        replacement = [seed("merged-root-a"), seed("merged-root-b")]
        recovery = create_recovery(
            [legion_wide, peer_state],
            self.recovery,
            replacement,
            2,
            revoke_embodiments=["embodiment:legion"],
        )

        recovered = verify_recovery(recovery, [legion_wide, peer_state])

        self.assertEqual(
            recovered.revocations["embodiment:legion"],
            {"cutoff_incarnation_sequence": 1, "revocation_generation": 2},
        )
        self.assertEqual(
            recovered.revocations["embodiment:daimonmatrix"],
            {"cutoff_incarnation_sequence": 4, "revocation_generation": 1},
        )

        jumped = create_revocation(
            self.state,
            self.root,
            embodiment_id="embodiment:attacker",
            cutoff_incarnation_sequence=0,
            revocation_generation=2,
        )
        with self.assertRaisesRegex(VerificationError, "increment exactly once"):
            verify_successor(jumped, self.state)

        widened = create_revocation(
            legion_strict,
            self.root,
            embodiment_id="embodiment:legion",
            cutoff_incarnation_sequence=2,
            revocation_generation=2,
        )
        with self.assertRaisesRegex(VerificationError, "less restrictive"):
            verify_successor(widened, legion_strict)


class ProvisionalBindingTests(IdentityFixture):
    def _history(self) -> tuple[bytes, list[dict[str, Any]], dict[str, Any]]:
        vector_root = ROOT / "vectors" / "weave" / "v1"
        manifest = json.loads((vector_root / "manifest.json").read_bytes())
        manifest_bytes = canonical_bytes(manifest)
        event = json.loads((vector_root / "configuration-proposal.json").read_bytes())
        head = {
            "content_hash": event["content_hash"],
            "event_id": event["event_id"],
            "incarnation_id": event["origin"]["incarnation_id"],
            "origin_embodiment_id": event["origin"]["embodiment_id"],
            "sequence": event["sequence"],
            "signer_key_id": event["signature"]["kid"],
        }
        return manifest_bytes, [head], event

    def test_binding_preserves_original_history_and_downgrade_fails(self) -> None:
        manifest_bytes, heads, event = self._history()
        before = canonical_bytes(event)
        binding = create_history_binding(
            self.state,
            self.root,
            provisional_being_ref="being:provisional",
            manifest_bytes=manifest_bytes,
            manifest_revision=1,
            accepted_heads=heads,
        )

        index = json.loads(
            (ROOT / "vectors" / "weave" / "v1" / "index.json").read_bytes()
        )

        def verify_head(head: Any) -> bool:
            core = {
                key: value
                for key, value in event.items()
                if key not in {"content_hash", "signature"}
            }
            digest_hex = hashlib.sha256(canonical_bytes(core)).hexdigest()
            if digest_hex != head["content_hash"]:
                return False
            public = unb64url(index["public_keys"][head["signer_key_id"]], length=32)
            try:
                Ed25519PublicKey.from_public_bytes(public).verify(
                    unb64url(event["signature"]["value"], length=64),
                    b"daimon/weave/event/v1\x00" + bytes.fromhex(digest_hex),
                )
            except Exception:
                return False
            return bool(event["event_id"] == head["event_id"])

        verify_history_binding(
            binding,
            self.state,
            manifest_bytes=manifest_bytes,
            manifest_revision=1,
            accepted_heads=heads,
            verify_head=verify_head,
        )
        self.assertEqual(before, canonical_bytes(event))

        mutations: list[dict[str, Any]] = [
            {"manifest_bytes": manifest_bytes + b" "},
            {"manifest_revision": 2},
            {"accepted_heads": []},
        ]
        baseline: dict[str, Any] = {
            "manifest_bytes": manifest_bytes,
            "manifest_revision": 1,
            "accepted_heads": heads,
        }
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                arguments = baseline | mutation
                with self.assertRaises(VerificationError):
                    verify_history_binding(
                        binding,
                        self.state,
                        verify_head=verify_head,
                        **arguments,
                    )

        activation = create_binding_activation(self.state, self.root, binding)
        activated = verify_binding_activation(activation, binding, self.state)
        require_trust_mode(activated, "root-bound")
        with self.assertRaises(VerificationError):
            require_trust_mode(activated, "provisional")


if __name__ == "__main__":
    unittest.main()
