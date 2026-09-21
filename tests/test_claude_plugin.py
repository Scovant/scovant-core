"""Pins the Claude Code plugin tree (claude-plugin/) to the package: version
lockstep, MCP pins, and generated references."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

PKG_ROOT = Path(__file__).resolve().parents[1]
PLUGIN = PKG_ROOT / "claude-plugin"
MARKETPLACE = PKG_ROOT / ".claude-plugin" / "marketplace.json"

if not (PKG_ROOT / "README.md").exists() or not PLUGIN.exists():
    pytestmark = pytest.mark.skip(reason="package tree not present (isolated run)")


def _version() -> str:
    return tomllib.loads((PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _plugin_json() -> dict:
    return json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))


def _mcp_json() -> dict:
    return json.loads((PLUGIN / ".mcp.json").read_text(encoding="utf-8"))


def test_plugin_version_is_the_package_version():
    v = _version()
    assert _plugin_json()["version"] == v
    market = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
    (entry,) = market["plugins"]
    assert entry["version"] == v
    assert entry["source"] == "./claude-plugin"


def test_plugin_json_uses_only_stable_fields():
    allowed = {"name", "version", "description", "author", "repository", "license", "keywords", "skills", "mcpServers"}
    pj = _plugin_json()
    assert set(pj) <= allowed, set(pj) - allowed
    assert pj["name"] == "scovant" and pj["skills"] == "./skills/" and pj["mcpServers"] == "./.mcp.json"


def test_mcp_json_pins_this_version_and_the_claude_code_medium():
    from scovant_core.report._cta import _MEDIA
    servers = _mcp_json()["mcpServers"]
    core = servers["scovant-core"]
    assert core["command"] == "uvx"
    assert f"scovant-core[mcp]=={_version()}" in core["args"]
    assert core["args"][-2:] == ["scovant", "mcp"]
    assert core["env"]["SCOVANT_CTA_MEDIUM"] == "claude-code" and "claude-code" in _MEDIA


def test_mcp_json_cloud_server_uses_the_literal_env_placeholder():
    cloud = _mcp_json()["mcpServers"]["scovant-cloud"]
    assert cloud["type"] == "http" and cloud["url"] == "https://scovant.com/mcp/"
    # ${VAR:-default} so an unset SCOVANT_API_KEY expands to "" (no
    # unresolved "${SCOVANT_API_KEY}" literal sent as a bearer token).
    assert cloud["headers"]["Authorization"] == "Bearer ${SCOVANT_API_KEY:-}"


def test_every_skill_has_frontmatter_name_and_description():
    skills = sorted(p.parent.name for p in PLUGIN.glob("skills/*/SKILL.md"))
    assert skills == ["ci", "cloud", "explain", "scan"]
    for p in PLUGIN.glob("skills/*/SKILL.md"):
        text = p.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        assert m, f"{p} has no frontmatter"
        assert re.search(r"^name: ", m.group(1), re.M) and re.search(r"^description: ", m.group(1), re.M)


def test_references_are_generated_not_hand_written():
    from scovant_core.docs import render_agentready, render_checks
    refs = PLUGIN / "skills" / "references"
    assert (refs / "checks.md").read_text(encoding="utf-8") == render_checks()
    assert (refs / "agentready.md").read_text(encoding="utf-8") == render_agentready()
    assert (refs / "methodology.md").read_bytes() == (PKG_ROOT / "docs" / "methodology.md").read_bytes()
    assert (refs / "report.schema.json").read_bytes() == (PKG_ROOT / "docs" / "report.schema.json").read_bytes()


def test_scan_skill_pins_the_same_version_in_its_cli_fallback():
    text = (PLUGIN / "skills" / "scan" / "SKILL.md").read_text(encoding="utf-8")
    assert f'scovant-core[mcp]=={_version()}' in text
    assert "--allow-private-networks" in text
