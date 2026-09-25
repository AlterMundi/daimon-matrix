"""Embodiment labels are derived presentation, never authority."""

from __future__ import annotations

import unittest

from daimon_matrix.labels import (
    LABEL_SCHEMA,
    MAX_LABEL_BYTES,
    LabelError,
    LabelIndex,
    body_ref_parts,
    derive_labels,
    discriminator,
    parse_selector,
    validate_registry,
)

BEING = "dm:being:v1:" + "A" * 43
OTHER = "dm:being:v1:" + "B" * 43
HERMES_BODY = "embodiment:195a923d-5896-4cce-83e6-4defcfa011f3"
CODEX_BODY = "embodiment:7469563e-8b5b-4a5a-a55f-840318518c9e"
REMOTE_BODY = "embodiment:f37a3f1a-a745-41e3-8d33-f84f230e616c"
SIBLING_BODY = "embodiment:00000000-1111-2222-3333-444444444444"


def registry(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": LABEL_SCHEMA,
        "beings": {BEING: "compaii", OTHER: "oliva"},
        "overrides": {
            HERMES_BODY: {"harness": "hermes"},
        },
    }
    value.update(overrides)
    return value


def entries() -> list[dict[str, str]]:
    return [
        {
            "being_ref": BEING,
            "embodiment_id": HERMES_BODY,
            "body_ref": "cli:legion:compaii-chat",
        },
        {
            "being_ref": BEING,
            "embodiment_id": CODEX_BODY,
            "body_ref": "codex:legion:compaii",
        },
        {
            "being_ref": BEING,
            "embodiment_id": REMOTE_BODY,
            "body_ref": "cluster:daimonmatrix:compaii",
        },
    ]


class TestRegistry(unittest.TestCase):
    def test_valid_registry_is_closed_and_normalized(self) -> None:
        result = validate_registry(registry())
        self.assertEqual(result["beings"][BEING], "compaii")
        self.assertEqual(result["overrides"][HERMES_BODY], {"harness": "hermes"})

    def test_rejects_wrong_schema_extra_keys_and_bad_names(self) -> None:
        for bad in (
            {**registry(), "schema": "dm.labels.registry/v2"},
            {**registry(), "extra": {}},
            {**registry(), "beings": {BEING: "CompAII"}},
            {**registry(), "beings": {"not-a-being-ref": "compaii"}},
            {**registry(), "overrides": {HERMES_BODY: {}}},
            {**registry(), "overrides": {HERMES_BODY: {"model": "qwen"}}},
            {**registry(), "overrides": {"plain": {"host": "legion"}}},
            "not-a-mapping",
        ):
            with self.subTest(bad=str(bad)[:60]), self.assertRaises(LabelError):
                validate_registry(bad)

    def test_rejects_one_name_for_two_beings(self) -> None:
        with self.assertRaises(LabelError) as caught:
            validate_registry(registry(beings={BEING: "compaii", OTHER: "compaii"}))
        self.assertEqual(str(caught.exception), "labels_being_name_duplicated")


class TestDerivation(unittest.TestCase):
    def test_derives_from_signed_body_facts_and_overrides(self) -> None:
        derived = derive_labels(entries(), registry())
        self.assertEqual(derived[HERMES_BODY].label, "compaii.hermes@legion")
        self.assertEqual(derived[CODEX_BODY].label, "compaii.codex@legion")
        self.assertEqual(derived[REMOTE_BODY].label, "compaii.cluster@daimonmatrix")
        self.assertEqual(derived[REMOTE_BODY].being_ref, BEING)

    def test_body_ref_shape_is_exact(self) -> None:
        self.assertEqual(
            body_ref_parts("codex:legion:compaii"), ("codex", "legion", "compaii")
        )
        for bad in ("legion:compaii", "codex::compaii", "", "a:b:c:d", "A:b:c"):
            with self.subTest(bad=bad), self.assertRaises(LabelError):
                body_ref_parts(bad)

    def test_missing_being_name_fails_closed(self) -> None:
        with self.assertRaises(LabelError) as caught:
            derive_labels(entries(), registry(beings={OTHER: "oliva"}))
        self.assertEqual(str(caught.exception), "labels_being_name_missing")

    def test_duplicated_and_malformed_entries_fail_closed(self) -> None:
        rows = entries()
        with self.assertRaises(LabelError):
            derive_labels([*rows, rows[0]], registry())
        with self.assertRaises(LabelError):
            derive_labels([{**rows[0], "body_ref": "nope"}], registry())

    def test_collision_gets_deterministic_discriminator(self) -> None:
        rows = [
            *entries(),
            {
                "being_ref": BEING,
                "embodiment_id": SIBLING_BODY,
                "body_ref": "codex:legion:compaii-second",
            },
        ]
        derived = derive_labels(rows, registry())
        expected = f"compaii.codex@legion-{discriminator(CODEX_BODY)}"
        labels = {derived[CODEX_BODY].label, derived[SIBLING_BODY].label}
        self.assertEqual(len(labels), 2)
        self.assertIn(expected, labels)
        self.assertTrue(all(len(item.encode()) <= MAX_LABEL_BYTES for item in labels))

    def test_explicit_discriminator_wins_and_stays_unique(self) -> None:
        rows = [
            entries()[1],
            {
                "being_ref": BEING,
                "embodiment_id": SIBLING_BODY,
                "body_ref": "codex:legion:compaii-second",
            },
        ]
        local = registry(
            overrides={
                CODEX_BODY: {"discriminator": "work"},
                SIBLING_BODY: {"discriminator": "home"},
            }
        )
        derived = derive_labels(rows, local)
        self.assertEqual(derived[CODEX_BODY].label, "compaii.codex@legion-work")
        self.assertEqual(derived[SIBLING_BODY].label, "compaii.codex@legion-home")


class TestResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.index = LabelIndex(entries(), registry())

    def test_one_label_resolves_one_body(self) -> None:
        (target,) = self.index.resolve("compaii.codex@legion")
        self.assertEqual(target.embodiment_id, CODEX_BODY)
        self.assertEqual(target.being_ref, BEING)

    def test_being_level_selector_resolves_every_embodiment(self) -> None:
        targets = self.index.resolve("compaii")
        self.assertEqual(len(targets), 3)
        self.assertEqual(
            [item.label for item in targets],
            sorted(item.label for item in targets),
        )
        self.assertFalse(parse_selector("compaii.codex@legion").being_level)
        self.assertTrue(parse_selector("compaii").being_level)

    def test_unknown_ambiguous_and_invalid_selectors_fail_closed(self) -> None:
        for bad in (
            "compaii.goose@legion",
            "nobody",
            "compaii.codex",
            "@legion",
            "compaii..codex@legion",
            "compaii codex@legion",
            "",
            None,
            "x" * 200,
        ):
            with self.subTest(bad=str(bad)[:40]), self.assertRaises(LabelError):
                self.index.resolve(bad)

    def test_label_of_unknown_body_fails_closed(self) -> None:
        with self.assertRaises(LabelError):
            self.index.label_of(SIBLING_BODY)

    def test_relabeling_never_changes_identity_refs(self) -> None:
        before = derive_labels(entries(), registry())[CODEX_BODY]
        after = derive_labels(
            entries(), registry(overrides={CODEX_BODY: {"harness": "goose"}})
        )[CODEX_BODY]
        self.assertEqual(before.label, "compaii.codex@legion")
        self.assertEqual(after.label, "compaii.goose@legion")
        self.assertEqual(before.being_ref, after.being_ref)
        self.assertEqual(before.embodiment_id, after.embodiment_id)

    def test_index_exposes_no_signing_or_verification_surface(self) -> None:
        public = {name for name in dir(self.index) if not name.startswith("_")}
        self.assertEqual(
            public,
            {
                "being_ref_of_name",
                "label_of",
                "resolve",
                "targets",
            },
        )


if __name__ == "__main__":
    unittest.main()
