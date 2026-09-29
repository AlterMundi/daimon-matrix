"""One active tribe per being, and why the rule lives at authoring time (#189).

`specs/tribe-conversation.md` §6 admits exactly one active tribe per being in V0. A
founded tribe can never be terminated: the original founder's membership is
unconditionally active and there is no dissolution event kind. So the rule is enforced
where it can be -- refusing to create a second tribe -- and never at resolution, where
it would permanently brick a being that already has more than one.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from daimon_matrix.canonical import b64url
from daimon_matrix.relationship_store import (
    active_tribe_refs,
    blocking_active_tribes,
)
from daimon_matrix.relationships import DECLARATION_SCHEMA, tribe_ref
from daimon_matrix.synthetic_relationships import _Journey, _seed


def _permissive_card_verifier(_card: Any, _at_ms: int) -> None:
    return None


class SingleActiveTribeTests(unittest.TestCase):
    def journey(self) -> tuple[_Journey, Any]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        journey = _Journey(Path(temporary.name))
        journey.run()
        view = journey.store.view(
            at_ms=journey.now, card_verifier=_permissive_card_verifier
        )
        return journey, view

    def second_tribe(self, journey: _Journey) -> str:
        """Author one more founded tribe for the same founder, as a legacy store has."""

        core = {
            "created_at_ms": journey.now + 90,
            "founder_principal_id": journey.identities["founder"].state.being_ref,
            "nonce": b64url(_seed("tribe:second")),
            "policy_ref": "dm:tribe-policy:v1:synthetic-second",
        }
        reference = tribe_ref(core)
        journey.append(
            "founder",
            "matrix/tribe-declaration",
            {
                "schema": DECLARATION_SCHEMA,
                "tribe_ref": reference,
                "declaration": core,
            },
            at_ms=journey.now + 90,
        )
        return reference

    def members_of(self, view: Any) -> tuple[str, dict[str, Any], str, str]:
        """One tribe, its original founder and one accepted member, from the store.

        Read out of the store rather than out of the fixture's labels. The journey
        also exercises a founder transfer, so ``founder_being_ref`` is the *current*
        founder at a later epoch; the being whose membership is synthesized from the
        declaration is the original one, named by the declaration itself.
        """

        self.assertEqual(len(view.tribes), 1)
        tribe, info = next(iter(view.tribes.items()))
        self.assertEqual(info["state"], "active")
        original = info["declaration"]["payload"]["declaration"]["founder_principal_id"]
        accepted = [
            member
            for member, membership in info["memberships"].items()
            if membership["episodes"]
        ]
        self.assertEqual(len(accepted), 1)
        return tribe, info, original, accepted[0]

    def test_founder_membership_is_synthesized_and_still_counts(self) -> None:
        _journey, view = self.journey()
        tribe, info, original, _accepted = self.members_of(view)
        membership = info["memberships"][original]
        # The original founder's membership has no acceptance behind it. This is the
        # fact the whole rule turns on: a helper that counted only acceptance episodes
        # would see this founder in no tribe at all, and since a founded tribe can
        # never be terminated the rule would never fire for exactly the being that
        # cannot leave it.
        self.assertEqual(membership["state"], "active")
        self.assertEqual(membership["episodes"], [])
        episodes_only = [
            candidate
            for candidate, candidate_info in view.tribes.items()
            if candidate_info["state"] == "active"
            and (candidate_info["memberships"].get(original) or {}).get("episodes")
        ]
        self.assertEqual(episodes_only, [], "the negative control must be empty")
        self.assertEqual(active_tribe_refs(view, original), (tribe,))

    def test_accepting_member_counts_and_unrelated_being_does_not(self) -> None:
        journey, view = self.journey()
        tribe, _info, original, accepted = self.members_of(view)
        self.assertEqual(active_tribe_refs(view, accepted), (tribe,))
        self.assertEqual(active_tribe_refs(view, original), (tribe,))
        outsider = journey.identities["delegate"].state.being_ref
        self.assertNotIn(outsider, _info["memberships"])
        self.assertEqual(
            active_tribe_refs(view, outsider),
            (),
            "a being that never accepted is not a member",
        )

    def test_blocking_filter_separates_creating_from_rejoining(self) -> None:
        journey, view = self.journey()
        tribe, _info, original, _accepted = self.members_of(view)
        # Founding another tribe is what §6 forbids.
        self.assertEqual(
            blocking_active_tribes(view, original, tribe_ref=None), (tribe,)
        )
        # Re-admission into the same tribe is a membership question, not a second one.
        self.assertEqual(blocking_active_tribes(view, original, tribe_ref=tribe), ())
        # A being with no tribe is unrestricted, so a fresh body is unaffected.
        outsider = journey.identities["delegate"].state.being_ref
        self.assertEqual(blocking_active_tribes(view, outsider, tribe_ref=None), ())

    def test_legacy_store_with_two_active_tribes_keeps_both_resolvable(self) -> None:
        journey, first_view = self.journey()
        _tribe, _info, original, _accepted = self.members_of(first_view)
        second = self.second_tribe(journey)
        view = journey.store.view(
            at_ms=journey.now + 91, card_verifier=_permissive_card_verifier
        )
        both = active_tribe_refs(view, original)
        self.assertEqual(len(both), 2)
        self.assertEqual(both, tuple(sorted(both)))
        self.assertIn(second, both)
        # The rule is forward-only precisely so this state stays usable: each tribe is
        # still resolvable by the explicit tribe_ref every artifact carries. Refusing
        # at resolution instead would brick the first tribe too, with no repair.
        for reference in both:
            self.assertEqual(view.tribes[reference]["state"], "active")
            snapshot = view.snapshot(reference)
            self.assertEqual(snapshot.value["tribe_ref"], reference)
            self.assertIn(
                original,
                {member["principal_id"] for member in snapshot.value["members"]},
            )
        # And founding a third is what the authoring path now refuses, while an
        # operation naming one of the two existing tribes is not this rule's to stop.
        self.assertEqual(len(blocking_active_tribes(view, original, tribe_ref=None)), 2)
        other = next(item for item in both if item != second)
        self.assertEqual(
            blocking_active_tribes(view, original, tribe_ref=second), (other,)
        )


if __name__ == "__main__":
    unittest.main()
