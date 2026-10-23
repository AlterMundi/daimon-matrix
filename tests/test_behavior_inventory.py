"""Useful configuration survives private bindings and unknown defaults stay unknown."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools import behavior_inventory as tool


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.codex = self.home / ".codex"
        self.cwd = self.home / "project"
        self.codex.mkdir(parents=True)
        self.cwd.mkdir()
        self.evidence = self.root / "loader.rs"
        self.evidence.write_text("// Exact receiving source fixture\n")

    def discover(self):
        return tool.discover(
            home=self.home,
            codex_home=self.codex,
            cwd=self.cwd,
            version="fixture",
            source_revision="a" * 40,
            source_evidence=self.evidence,
        )

    def test_dynamic_settings_and_external_reference_without_execution(self):
        extra = self.home / "custom.md"
        extra.write_text("Keep origin attribution.\n")
        (self.codex / "config.toml").write_text(
            'future_feature = true\nmodel_instructions_file = "~/custom.md"\n'
            '[mcp_servers.custom]\ncommand = "/missing/helper"\n'
            "[mcp_servers.custom.env]\n"
            'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz012345"\n'
        )
        result = self.discover()
        config = result["configuration"][0]
        settings = {tuple(s["key"]): s for s in config["settings"]}
        self.assertEqual(
            settings[("future_feature",)]["baseline_state"], "unknown_default"
        )
        self.assertEqual(
            settings[("mcp_servers", "custom", "env", "API_KEY")],
            dict(
                key=["mcp_servers", "custom", "env", "API_KEY"],
                state="private_binding_omitted",
            ),
        )
        refs = {r["path"]: r for r in config["references"]}
        self.assertEqual(
            refs[str(extra)]["sha256"], tool.describe_file(extra)["sha256"]
        )
        self.assertEqual(refs["/missing/helper"]["state"], "absent")
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz012345", json.dumps(result))
        self.assertFalse(any(result["effects"].values()))

    def test_baseline_type_and_missing_keys_are_not_false_defaults(self):
        config = self.codex / "config.toml"
        config.write_text("count = 1\nexperimental = true\n")
        rows = tool.configuration(config, home=self.home, defaults={"count": True})[
            "settings"
        ]
        self.assertEqual(rows[0]["baseline_state"], "modified")
        self.assertEqual(rows[1]["baseline_state"], "unknown_default")
        self.assertEqual(
            tool.configuration(config, home=self.home, defaults={"count": 1})[
                "settings"
            ][0]["baseline_state"],
            "inherited",
        )

    def test_global_override_precedence_and_alias_stay_explicit(self):
        (self.codex / "AGENTS.md").write_text("Historical fallback\n")
        override = self.codex / "AGENTS.override.md"
        override.write_text("Current customization\n")
        rows = self.discover()["instructions"]
        self.assertEqual(
            [r["path"] for r in rows if r["scope"] == "global"], [str(override)]
        )
        override.unlink()
        override.symlink_to(self.home / "unknown")
        rows = self.discover()["instructions"]
        self.assertEqual(rows[0]["state"], "private_or_unresolved_source")
        self.assertEqual(len([r for r in rows if r["scope"] == "global"]), 1)

    def test_native_baseline_is_exact_and_unspecified_is_not_a_default(self):
        current = self.root / "current.json"
        baseline = self.root / "baseline.json"

        def packet(value, binary="a" * 64):
            return dict(binary_sha256=binary, result=dict(config=value, layers=[]))

        current.write_text(json.dumps(packet(dict(model="selected", custom=True))))
        baseline.write_text(json.dumps(packet(dict(model=None))))
        result = tool.native_comparison(current, baseline)
        self.assertEqual(
            [s["baseline_state"] for s in result["settings"]],
            ["unknown_default", "baseline_unspecified"],
        )
        self.assertEqual(result["running_turn_consumption"], "unverified")
        baseline.write_text(json.dumps(packet({}, binary="b" * 64)))
        with self.assertRaisesRegex(ValueError, "matching_native_binary"):
            tool.native_comparison(current, baseline)

    def test_private_native_setting_is_not_republished_in_report(self):
        current = self.root / "current.json"
        current.write_text(
            json.dumps(
                dict(
                    binary_sha256="a" * 64,
                    result=dict(
                        config=dict(
                            mcp_servers=dict(test=dict(bearer_token="sensitive"))
                        ),
                        layers=[],
                    ),
                )
            )
        )
        result = tool.native_comparison(current, None)
        row = result["settings"][0]
        self.assertEqual(row["state"], "private_binding_omitted")
        self.assertNotIn("value_sha256", row)
        self.assertNotIn("sensitive", json.dumps(result))

    def test_token_limits_and_credential_backend_are_behavior_not_secrets(self):
        config = self.codex / "config.toml"
        config.write_text(
            "model_auto_compact_token_limit = 20000\n"
            'cli_auth_credentials_store = "file"\n'
        )
        rows = tool.configuration(config, home=self.home)["settings"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all("value_sha256" in r for r in rows))

    def test_three_way_preview_preserves_manual_conflicts_and_cross_being_boundary(
        self,
    ):
        import copy

        base = self.discover()
        base["origin"] = dict(being_ref="same-being", body_ref="original-body")
        base["native_configuration"] = dict(
            settings=[dict(key=["style"], value_sha256="a" * 64)]
        )
        left, right = copy.deepcopy(base), copy.deepcopy(base)
        left["native_configuration"]["settings"][0]["value_sha256"] = "b" * 64
        right["native_configuration"]["settings"][0]["value_sha256"] = "c" * 64
        right["origin"]["body_ref"] = "other-body"
        result = tool.compare(left, right, base)
        self.assertEqual(result["entries"][0]["state"], "conflicting_edits")
        self.assertFalse(any(result["effects"].values()))
        self.assertEqual(
            tool.compare(base, right, base)["entries"][0]["state"], "incoming_changed"
        )
        self.assertEqual(
            tool.compare(left, right)["entries"][0]["state"],
            "different_without_common_history",
        )
        right["origin"]["being_ref"] = "different-being"
        with self.assertRaisesRegex(ValueError, "same_being_inventory"):
            tool.compare(left, right)

    def test_project_layers_and_skill_aliases_preserve_gaps(self):
        (self.home / "AGENTS.md").write_text("Parent instructions\n")
        (self.cwd / ".codex").mkdir()
        (self.cwd / ".codex/config.toml").write_text("new_setting = false\n")
        skills = self.home / ".agents/skills"
        skills.mkdir(parents=True)
        (skills / "alias").symlink_to(self.root / "outside")
        result = self.discover()
        self.assertEqual(len(result["configuration"]), 2)
        self.assertTrue(
            any(
                r["path"] == str(self.home / "AGENTS.md")
                for r in result["instructions"]
            )
        )
        self.assertEqual(
            result["skills"][0]["omissions"][0]["reason"], "unresolved_symlink"
        )
        self.assertTrue(result["gaps"])


if __name__ == "__main__":
    unittest.main()
