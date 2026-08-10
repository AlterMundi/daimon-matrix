#!/usr/bin/env python3
"""Generate and verify frozen DM-074 profiles, fixture, reports, and sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "harness" / "v0"))

from checker import (  # noqa: E402
    FORBIDDEN_METHODS,
    MANDATORY_CONTROLS,
    PROFILE_SCHEMA,
    PROTOCOL_VERSION,
    REQUIRED_TOOLS,
    WRITE_TOOLS,
    conformance_report,
    fixture_manifest,
)

ACCESSED_ON = "2026-08-10"
BASE_COMMIT = "dad012d669947a81b26d847035787caa937f8705"


def _source(
    source_id: str,
    *,
    owner: str,
    title: str,
    url: str,
    pin: str,
    content_digest: str,
) -> dict[str, str]:
    return {
        "accessed_on": ACCESSED_ON,
        "content_digest": content_digest,
        "owner": owner,
        "pin": pin,
        "source_id": source_id,
        "title": title,
        "url": url,
    }


SOURCES = [
    _source(
        "anthropic-claude-mcp-20260810",
        owner="Anthropic",
        title="Connect Claude Code to tools via MCP",
        url="https://code.claude.com/docs/en/mcp",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:2464fb590121cb0664ce5de16b2bcec8c145c025c9f02674435c749434c2c40e"
        ),
    ),
    _source(
        "anthropic-claude-memory-20260810",
        owner="Anthropic",
        title="How Claude remembers your project",
        url="https://code.claude.com/docs/en/memory",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:870a8769df10ba121996fa31786dd13d3086f16a20825bb5480f6b1586866bca"
        ),
    ),
    _source(
        "anthropic-claude-permissions-20260810",
        owner="Anthropic",
        title="Configure permissions",
        url="https://code.claude.com/docs/en/permissions",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:b526efff3e26518041d6b38d7656002c926aa18a47d7c8f1a2c272467f1b3dd2"
        ),
    ),
    _source(
        "antigravity-mcp-20260810",
        owner="Google",
        title="Antigravity Editor MCP integration",
        url="https://www.antigravity.google/docs/mcp",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:2676c327c8dcd0468ddc6711954b4dc7cd272e92a84b3b15227b54bca9d0abaf"
        ),
    ),
    _source(
        "antigravity-permissions-20260810",
        owner="Google",
        title="Antigravity CLI permissions",
        url="https://www.antigravity.google/docs/cli-permissions",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:d8d059bac2da9f87931c876575bee0fa1059ba03b19ededff5d95fc93338c2e2"
        ),
    ),
    _source(
        "antigravity-plugins-20260810",
        owner="Google",
        title="Antigravity plugins",
        url="https://www.antigravity.google/docs/plugins",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:a5a03dece9a353590cea082fdfd81b2bb66a91bc44cdbeda02e1f9443774a66b"
        ),
    ),
    _source(
        "dm025-generic-mcp",
        owner="AlterMundi",
        title="DM-025 CLI and MCP boundary",
        url="docs/dm025-cli-mcp.md",
        pin=BASE_COMMIT,
        content_digest=(
            "sha256:ad7bcf543c77fbaee9d228aaf449387fba20492359d0925bd5c63bcfbe167d2f"
        ),
    ),
    _source(
        "dm040-codex-0-146-0",
        owner="AlterMundi",
        title="DM-040 exact Codex body adapter",
        url="docs/dm040-codex-body.md",
        pin=BASE_COMMIT,
        content_digest=(
            "sha256:51baa0c703276f32d9d9588980ed23e1e8a8141ead5b8b7b36761377a812136d"
        ),
    ),
    _source(
        "kimi-code-config-27f5f03f",
        owner="Moonshot AI",
        title="Kimi Code configuration files",
        url=(
            "https://github.com/MoonshotAI/kimi-code/blob/"
            "0401ec4286f37929d1d298527c05f5351850bf8a/"
            "docs/en/configuration/config-files.md"
        ),
        pin="git-blob:27f5f03f36678bfe3565af27fe6e714d47bc26ae",
        content_digest="git-blob-sha1:27f5f03f36678bfe3565af27fe6e714d47bc26ae",
    ),
    _source(
        "kimi-code-mcp-a6533c38",
        owner="Moonshot AI",
        title="Kimi Code MCP",
        url=(
            "https://github.com/MoonshotAI/kimi-code/blob/"
            "0401ec4286f37929d1d298527c05f5351850bf8a/"
            "docs/en/customization/mcp.md"
        ),
        pin="git-blob:a6533c38f6b053db7a136f0b72bb5cad7160f1b6",
        content_digest="git-blob-sha1:a6533c38f6b053db7a136f0b72bb5cad7160f1b6",
    ),
    _source(
        "kimi-code-migration-191cc5fa",
        owner="Moonshot AI",
        title="Kimi Code migration",
        url=(
            "https://github.com/MoonshotAI/kimi-code/blob/"
            "0401ec4286f37929d1d298527c05f5351850bf8a/"
            "docs/en/guides/migration.md"
        ),
        pin="git-blob:191cc5fa05064af7415b12344b5279fc52b3ed21",
        content_digest="git-blob-sha1:191cc5fa05064af7415b12344b5279fc52b3ed21",
    ),
    _source(
        "kimi-code-sessions-b63ee8d2",
        owner="Moonshot AI",
        title="Kimi Code sessions",
        url=(
            "https://github.com/MoonshotAI/kimi-code/blob/"
            "0401ec4286f37929d1d298527c05f5351850bf8a/"
            "docs/en/guides/sessions.md"
        ),
        pin="git-blob:b63ee8d24a88123af8a12e8854b525a558574d93",
        content_digest="git-blob-sha1:b63ee8d24a88123af8a12e8854b525a558574d93",
    ),
    _source(
        "openai-codex-agents-20260810",
        owner="OpenAI",
        title="Custom instructions with AGENTS.md",
        url="https://learn.chatgpt.com/docs/agent-configuration/agents-md",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:47eb0fa36c6fe1322c6b1bd7eeff83c2312bb07452f22cd74c77e87455417425"
        ),
    ),
    _source(
        "openai-codex-config-20260810",
        owner="OpenAI",
        title="Codex configuration reference",
        url="https://learn.chatgpt.com/docs/config-file/config-reference",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:3845ccd3ff0b412628d3eb392acc56b6b0778ffb33d6f26077663e0e57029607"
        ),
    ),
    _source(
        "openai-codex-mcp-20260810",
        owner="OpenAI",
        title="Codex MCP configuration",
        url="https://learn.chatgpt.com/docs/extend/mcp?surface=cli",
        pin="retrieved-2026-08-10",
        content_digest=(
            "sha256:102ef3e6e4864378b964ed8be37be1115a9962de7286e3d78567a6a893579a33"
        ),
    ),
    _source(
        "xai-grok-config-13a3f7b7",
        owner="xAI",
        title="Grok Build configuration",
        url=(
            "https://github.com/xai-org/grok-build/blob/"
            "b13fa526f5112c0b20dad5f1f2300d3d3b127895/"
            "crates/codegen/xai-grok-pager/docs/user-guide/05-configuration.md"
        ),
        pin="git-blob:13a3f7b77f3ce0121e5400c8eb41b9da3a60280f",
        content_digest="git-blob-sha1:13a3f7b77f3ce0121e5400c8eb41b9da3a60280f",
    ),
    _source(
        "xai-grok-mcp-fce8f3c7",
        owner="xAI",
        title="Grok Build MCP servers",
        url=(
            "https://github.com/xai-org/grok-build/blob/"
            "b13fa526f5112c0b20dad5f1f2300d3d3b127895/"
            "crates/codegen/xai-grok-pager/docs/user-guide/07-mcp-servers.md"
        ),
        pin="git-blob:fce8f3c7cc78a8c85579e7bb2e64805eca2e82e0",
        content_digest="git-blob-sha1:fce8f3c7cc78a8c85579e7bb2e64805eca2e82e0",
    ),
    _source(
        "xai-grok-memory-c94cc4b5",
        owner="xAI",
        title="Grok Build memory",
        url=(
            "https://github.com/xai-org/grok-build/blob/"
            "b13fa526f5112c0b20dad5f1f2300d3d3b127895/"
            "crates/codegen/xai-grok-pager/docs/user-guide/13-memory.md"
        ),
        pin="git-blob:c94cc4b570fe31335883afe675943791782f723a",
        content_digest="git-blob-sha1:c94cc4b570fe31335883afe675943791782f723a",
    ),
    _source(
        "xai-grok-sandbox-098628c3",
        owner="xAI",
        title="Grok Build sandbox",
        url=(
            "https://github.com/xai-org/grok-build/blob/"
            "b13fa526f5112c0b20dad5f1f2300d3d3b127895/"
            "crates/codegen/xai-grok-pager/docs/user-guide/18-sandbox.md"
        ),
        pin="git-blob:098628c396fb95d4a68da2cc5f56edb4e8347dcc",
        content_digest="git-blob-sha1:098628c396fb95d4a68da2cc5f56edb4e8347dcc",
    ),
]


def _control(state: str, evidence: list[str], note: str) -> dict[str, Any]:
    return {"evidence": sorted(evidence), "note": note, "state": state}


def _pass(source: str, note: str) -> tuple[str, list[str], str]:
    return ("pass", [source], note)


def _unknown(source: str, note: str) -> tuple[str, list[str], str]:
    return ("unknown", [source], note)


def _fail(source: str, note: str) -> tuple[str, list[str], str]:
    return ("fail", [source], note)


def _candidate_controls(
    source: str, overrides: dict[str, tuple[str, list[str], str]]
) -> dict[str, tuple[str, list[str], str]]:
    result = {
        name: _unknown(source, "Not proven by the pinned candidate evidence.")
        for name in MANDATORY_CONTROLS
    }
    result.update(overrides)
    return result


def _overlay(prefix: str) -> dict[str, str]:
    return {
        "cleanup_policy": f"validated-disposable-{prefix}-root-only",
        "credential_channel": "inherited-descriptor-only",
        "effective_config_inspection": "required-before-admission",
        "history_policy": "disabled-or-refused",
        "home_isolation": f"fresh-owner-only-{prefix}-root",
        "instruction_policy": "matrix-overlay-guides-but-never-authorizes",
        "lifecycle_policy": "stable-start-turn-tool-receipt-park-wake-crash-resume-ids",
        "log_policy": "no-secrets-no-private-paths-no-transcript-authority",
        "memory_policy": "disabled-or-subordinate-and-rebuildable",
        "network_policy": "default-deny-no-public-tunnel",
        "retry_policy": "same-id-same-bytes-only-different-bytes-conflict",
    }


def _profile(
    profile_id: str,
    *,
    name: str,
    vendor: str,
    version: str,
    surface: str,
    source_refs: list[str],
    evidence_state: str,
    admission_reason: str,
    controls: dict[str, tuple[str, list[str], str]],
    install_source: str,
    executable_sha256: str | None,
    config_precedence: str,
    state_roots: list[str],
    auto_update_policy: str,
    migration_policy: str,
    limitations: list[str],
    launch_argv: list[str],
    launch_configuration: list[str],
    launch_environment: list[str],
    requires_real_vendor_smoke: bool,
) -> dict[str, Any]:
    expected = (
        "accepted"
        if all(controls[name][0] == "pass" for name in MANDATORY_CONTROLS)
        else "refused"
    )
    return {
        "admission": {
            "expected": expected,
            "reason_code": admission_reason,
            "requires_real_vendor_smoke": requires_real_vendor_smoke,
        },
        "artifact": {
            "auto_update_policy": auto_update_policy,
            "config_precedence": config_precedence,
            "executable_sha256": executable_sha256,
            "install_source": install_source,
            "limitations": sorted(limitations),
            "migration_policy": migration_policy,
            "state_roots": sorted(state_roots),
        },
        "controls": {key: _control(*controls[key]) for key in MANDATORY_CONTROLS},
        "evidence_state": evidence_state,
        "harness": {
            "name": name,
            "source_refs": sorted(source_refs),
            "surface": surface,
            "vendor": vendor,
            "version": version,
        },
        "launch": {
            "argv": launch_argv,
            "configuration": sorted(launch_configuration),
            "environment": sorted(launch_environment),
            "status": (
                "synthetic-verified" if expected == "accepted" else "reference-only"
            ),
        },
        "matrix_boundary": {
            "forbidden_methods": list(FORBIDDEN_METHODS),
            "harness_is_being_authority": False,
            "harness_memory_is_canonical": False,
            "matrix_revalidates_effects": True,
            "protocol_version": PROTOCOL_VERSION,
            "required_tools": list(REQUIRED_TOOLS),
            "server_name": "matrix",
            "transport": "local-inherited-descriptor",
            "write_tools": list(WRITE_TOOLS),
        },
        "overlay": _overlay(profile_id),
        "profile_id": profile_id,
        "schema": PROFILE_SCHEMA,
    }


def _all_pass(source: str) -> dict[str, tuple[str, list[str], str]]:
    notes = {
        "profile_isolation": "Fresh owner-only state root with no ambient fallback.",
        "lifecycle_boundaries": (
            "Stable process, session, turn, tool, park, wake, crash and resume IDs."
        ),
        "instruction_precedence_audited": (
            "Effective instruction precedence is frozen and inspected."
        ),
        "required_matrix_boundary": (
            "The exact local Matrix boundary is startup-required."
        ),
        "tool_allowlist": "Only the six frozen Matrix tools are visible.",
        "write_approval": (
            "The sole write is separately gated and Matrix revalidates it."
        ),
        "network_default_deny": "The reference profile has no ambient network access.",
        "native_memory_disabled": "Native harness memory is disabled.",
        "history_persistence_disabled": "Harness transcript persistence is disabled.",
        "secret_custody": (
            "Capabilities use inherited descriptors and public evidence is scanned."
        ),
        "receipt_retry": (
            "Request IDs, receipts, crash recovery and retry are deterministic."
        ),
        "proposal_only": (
            "The harness can only read and propose a non-adopting observation."
        ),
        "authority_refusal": (
            "Identity, ledger, key, grant and deployment methods are refused."
        ),
        "lifecycle_receipts": (
            "Every accepted lifecycle transition has a bound receipt."
        ),
        "version_pinned": "Executable and protocol inputs are exact-pinned.",
        "upgrade_migration_closed": (
            "Updates and profile migration fail closed pending revalidation."
        ),
    }
    return {name: _pass(source, notes[name]) for name in MANDATORY_CONTROLS}


CHECKER_DIGEST = hashlib.sha256(
    (ROOT / "tests" / "fixtures" / "harness" / "v0" / "checker.py").read_bytes()
).hexdigest()

PROFILES = [
    _profile(
        "claude-code",
        name="Claude Code",
        vendor="Anthropic",
        version="documentation-snapshot-2026-08-10",
        surface="cli-stdio-mcp",
        source_refs=[
            "anthropic-claude-mcp-20260810",
            "anthropic-claude-memory-20260810",
            "anthropic-claude-permissions-20260810",
        ],
        evidence_state="documented-candidate",
        admission_reason="exact-executable-lifecycle-history-and-receipts-unproven",
        controls=_candidate_controls(
            "anthropic-claude-mcp-20260810",
            {
                "instruction_precedence_audited": _pass(
                    "anthropic-claude-memory-20260810",
                    "Documented instruction order can be audited, but is not "
                    "authority.",
                ),
                "native_memory_disabled": _pass(
                    "anthropic-claude-memory-20260810",
                    "Auto memory can be disabled in a future exact profile.",
                ),
                "network_default_deny": _pass(
                    "anthropic-claude-permissions-20260810",
                    "Sandbox network restrictions are documented.",
                ),
                "tool_allowlist": _pass(
                    "anthropic-claude-permissions-20260810",
                    "MCP tools can be allowed and denied by name.",
                ),
                "write_approval": _pass(
                    "anthropic-claude-permissions-20260810",
                    "Permissions can ask before the single write.",
                ),
            },
        ),
        install_source="not-installed-documentation-audit-only",
        executable_sha256=None,
        config_precedence="managed-settings-before-user-project-and-cli-requires-real-inspection",
        state_roots=["fresh-dedicated-claude-configuration-root-required"],
        auto_update_policy="disable-and-pin-before-any-real-smoke",
        migration_policy="no-import-of-personal-claude-profile-memory-or-sessions",
        limitations=[
            "exact-required-mcp-startup-gate-unproven",
            "lifecycle-receipt-adapter-unimplemented",
            "transcript-disablement-unproven",
        ],
        launch_argv=["claude", "<matrix-task>"],
        launch_configuration=[
            "auto-memory=disabled",
            "matrix-mcp=local-stdio-required",
            "permissions=deny-default-ask-we-observe",
        ],
        launch_environment=["CLAUDE_CONFIG_DIR=<validated-disposable-root>"],
        requires_real_vendor_smoke=True,
    ),
    _profile(
        "codex-cli",
        name="Codex CLI",
        vendor="OpenAI",
        version="0.146.0",
        surface="app-server-stdio",
        source_refs=[
            "dm040-codex-0-146-0",
            "openai-codex-agents-20260810",
            "openai-codex-config-20260810",
            "openai-codex-mcp-20260810",
        ],
        evidence_state="synthetic-conformant",
        admission_reason="exact-dm040-adapter-and-dm074-synthetic-corpus",
        controls=_all_pass("dm040-codex-0-146-0"),
        install_source="npm-openai-codex-0-146-0-audited-by-dm040",
        executable_sha256=(
            "2e863156ed35ecc5253b1e2f907a9143077b9f7cb51942070c61996471ff6e04"
        ),
        config_precedence="dm040-frozen-cli-managed-user-project-effective-chain",
        state_roots=["fresh-owner-only-codex-home"],
        auto_update_policy="exact-version-only-auto-update-disabled",
        migration_policy="no-personal-profile-session-or-memory-import",
        limitations=["not-live-supported", "provider-model-not-invoked-by-dm074"],
        launch_argv=["codex", "app-server"],
        launch_configuration=[
            "history.persistence=none",
            "mcp_servers.matrix.required=true",
            "web_search=disabled",
        ],
        launch_environment=["CODEX_HOME=<validated-disposable-root>"],
        requires_real_vendor_smoke=False,
    ),
    _profile(
        "generic-mcp-cli",
        name="Generic MCP or CLI host",
        vendor="vendor-neutral",
        version="dm074-fixture-v0",
        surface="local-inherited-descriptor",
        source_refs=["dm025-generic-mcp"],
        evidence_state="synthetic-conformant",
        admission_reason="matrix-owned-vendor-neutral-fixture",
        controls=_all_pass("dm025-generic-mcp"),
        install_source=f"daimon-matrix-{BASE_COMMIT}-harness-checker",
        executable_sha256=CHECKER_DIGEST,
        config_precedence="single-generated-overlay-no-vendor-precedence",
        state_roots=["fresh-owner-only-disposable-supervisor-root"],
        auto_update_policy="protocol-version-change-requires-new-profile",
        migration_policy="no-ambient-state-import-or-fallback",
        limitations=["not-a-claim-about-any-unknown-vendor-host"],
        launch_argv=[
            "python",
            "tests/fixtures/harness/v0/checker.py",
            "--fixture",
            "<fixture>",
            "<profile>",
        ],
        launch_configuration=[
            "only-matrix-local-endpoint",
            "protocol-version=0",
        ],
        launch_environment=["HARNESS_HOME=<validated-disposable-root>"],
        requires_real_vendor_smoke=False,
    ),
    _profile(
        "google-antigravity",
        name="Google Antigravity",
        vendor="Google",
        version="documentation-snapshot-2026-08-10",
        surface="editor-cli-mcp",
        source_refs=[
            "antigravity-mcp-20260810",
            "antigravity-permissions-20260810",
            "antigravity-plugins-20260810",
        ],
        evidence_state="documented-candidate",
        admission_reason="isolation-lifecycle-native-state-and-version-unproven",
        controls=_candidate_controls(
            "antigravity-mcp-20260810",
            {
                "network_default_deny": _pass(
                    "antigravity-permissions-20260810",
                    "Documented deny rules can close known network tools.",
                ),
                "tool_allowlist": _pass(
                    "antigravity-permissions-20260810",
                    "MCP resources support allow, ask and deny with deny precedence.",
                ),
                "write_approval": _pass(
                    "antigravity-permissions-20260810",
                    "Ask rules can gate the proposed write.",
                ),
            },
        ),
        install_source="not-installed-documentation-audit-only",
        executable_sha256=None,
        config_precedence="plugins-rules-skills-hooks-and-mcp-order-not-fully-proven",
        state_roots=["disposable-os-home-required-but-exact-product-root-unproven"],
        auto_update_policy="unknown-release-channel-refuses-canary",
        migration_policy="no-shared-gemini-or-antigravity-profile-import",
        limitations=[
            "headless-lifecycle-contract-unproven",
            "native-memory-and-history-disablement-unproven",
            "version-pin-unavailable-in-audited-docs",
        ],
        launch_argv=["<unbound-antigravity-executable>"],
        launch_configuration=[
            "all-plugins-disabled-except-matrix-overlay",
            "matrix-mcp=local-only",
            "permissions=deny-default-ask-we-observe",
        ],
        launch_environment=["HOME=<validated-disposable-os-home>"],
        requires_real_vendor_smoke=True,
    ),
    _profile(
        "grok-build",
        name="Grok Build",
        vendor="xAI",
        version="source-commit-b13fa526f5112c0b20dad5f1f2300d3d3b127895",
        surface="cli-headless-mcp",
        source_refs=[
            "xai-grok-config-13a3f7b7",
            "xai-grok-mcp-fce8f3c7",
            "xai-grok-memory-c94cc4b5",
            "xai-grok-sandbox-098628c3",
        ],
        evidence_state="documented-candidate",
        admission_reason="persistent-sessions-required-mcp-and-receipts-unproven",
        controls=_candidate_controls(
            "xai-grok-config-13a3f7b7",
            {
                "history_persistence_disabled": _fail(
                    "xai-grok-config-13a3f7b7",
                    "Headless sessions persist in SQLite; no exact no-history switch "
                    "is frozen.",
                ),
                "instruction_precedence_audited": _pass(
                    "xai-grok-config-13a3f7b7",
                    "Configuration precedence and project trust are documented.",
                ),
                "native_memory_disabled": _pass(
                    "xai-grok-memory-c94cc4b5",
                    "The highest-precedence no-memory switch can disable memory.",
                ),
                "network_default_deny": _pass(
                    "xai-grok-sandbox-098628c3",
                    "An exact custom Linux sandbox can fail closed.",
                ),
                "profile_isolation": _pass(
                    "xai-grok-config-13a3f7b7",
                    "GROK_HOME relocates the profile root.",
                ),
                "tool_allowlist": _pass(
                    "xai-grok-mcp-fce8f3c7",
                    "Headless tool filters can close the exposed inventory.",
                ),
                "write_approval": _pass(
                    "xai-grok-config-13a3f7b7",
                    "Headless approval filters can separately gate the write.",
                ),
            },
        ),
        install_source="not-installed-exact-public-source-audit-only",
        executable_sha256=None,
        config_precedence="exact-source-documents-cli-environment-and-grok-home-order",
        state_roots=["fresh-grok-home-required"],
        auto_update_policy="build-from-exact-source-commit-only",
        migration_policy="disable-claude-import-and-cross-session-memory",
        limitations=[
            "headless-history-persists",
            "matrix-lifecycle-receipt-adapter-unimplemented",
            "required-mcp-startup-gate-unproven",
        ],
        launch_argv=["grok", "--no-memory", "--headless"],
        launch_configuration=[
            "builtin-web-tools=disabled",
            "custom-linux-sandbox=fail-closed",
            "matrix-mcp=local-only",
        ],
        launch_environment=["GROK_HOME=<validated-disposable-root>"],
        requires_real_vendor_smoke=True,
    ),
    _profile(
        "kimi-code",
        name="Kimi Code CLI",
        vendor="Moonshot AI",
        version="source-commit-0401ec4286f37929d1d298527c05f5351850bf8a",
        surface="cli-acp-mcp",
        source_refs=[
            "kimi-code-config-27f5f03f",
            "kimi-code-mcp-a6533c38",
            "kimi-code-migration-191cc5fa",
            "kimi-code-sessions-b63ee8d2",
        ],
        evidence_state="documented-candidate",
        admission_reason="persistent-sessions-open-builtins-and-auto-update",
        controls=_candidate_controls(
            "kimi-code-config-27f5f03f",
            {
                "history_persistence_disabled": _fail(
                    "kimi-code-sessions-b63ee8d2",
                    "Sessions persist and no complete no-history mode is pinned.",
                ),
                "profile_isolation": _pass(
                    "kimi-code-config-27f5f03f",
                    "KIMI_CODE_HOME relocates Kimi Code state.",
                ),
                "tool_allowlist": _pass(
                    "kimi-code-config-27f5f03f",
                    "Global tools enabled and disabled lists are enforced before "
                    "execution.",
                ),
                "write_approval": _pass(
                    "kimi-code-config-27f5f03f",
                    "Ordered allow, deny and ask rules can gate tools.",
                ),
                "upgrade_migration_closed": _fail(
                    "kimi-code-migration-191cc5fa",
                    "Migration exists and TUI auto-install defaults on; both require "
                    "closure.",
                ),
            },
        ),
        install_source="not-installed-exact-current-kimi-code-source-audit-only",
        executable_sha256=None,
        config_precedence="environment-overrides-config-project-mcp-and-runtime-rules",
        state_roots=["fresh-kimi-code-home-required"],
        auto_update_policy="tui-auto-install-must-be-disabled-before-smoke",
        migration_policy="never-import-kimi-cli-claude-codex-or-personal-sessions",
        limitations=[
            "built-in-service-and-subagent-surface-not-yet-closed",
            "current-kimi-code-and-legacy-kimi-cli-contracts-not-interchangeable",
            "session-history-persistence-not-disabled",
        ],
        launch_argv=["kimi", "-p", "<matrix-task>"],
        launch_configuration=[
            "default_permission_mode=manual",
            "telemetry=false",
            "tools.enabled=matrix-only",
            "upgrade.auto_install=false",
        ],
        launch_environment=["KIMI_CODE_HOME=<validated-disposable-root>"],
        requires_real_vendor_smoke=True,
    ),
]


def _bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def _write_or_check(path: Path, value: Any, *, check: bool) -> bool:
    expected = _bytes(value)
    if check:
        return path.is_file() and path.read_bytes() == expected
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(expected)
    return True


def generate(*, check: bool) -> bool:
    fixture = fixture_manifest()
    profile_root = ROOT / "profiles" / "harness" / "v0"
    report_root = ROOT / "tests" / "fixtures" / "harness" / "v0"
    expected_profile_paths: set[Path] = set()
    expected_report_paths: set[Path] = {report_root / "manifest.json"}
    ok = _write_or_check(report_root / "manifest.json", fixture, check=check)
    for profile in PROFILES:
        profile_path = profile_root / f"{profile['profile_id']}.json"
        report_path = report_root / f"{profile['profile_id']}.report.json"
        expected_profile_paths.add(profile_path)
        expected_report_paths.add(report_path)
        ok = _write_or_check(profile_path, profile, check=check) and ok
        ok = (
            _write_or_check(
                report_path,
                conformance_report(profile, fixture),
                check=check,
            )
            and ok
        )
    inventory = {
        "accessed_on": ACCESSED_ON,
        "schema": "dm.harness-source-inventory/v0",
        "sources": SOURCES,
    }
    ok = (
        _write_or_check(
            ROOT / "provenance" / "harnesses-v0.json", inventory, check=check
        )
        and ok
    )
    if check:
        ok = set(profile_root.glob("*.json")) == expected_profile_paths and ok
        ok = set(report_root.glob("*.json")) == expected_report_paths and ok
    return ok


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if generate(check=arguments.check):
        return 0
    print("DM-074 generated artifacts drifted", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
