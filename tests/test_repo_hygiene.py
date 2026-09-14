"""Audit §22: citation target + support/templates ship with the package."""
import re
from pathlib import Path

import yaml

import scovant_core

ROOT = Path(__file__).resolve().parents[1]


def test_citation_cff_parses_and_pins_version():
    data = yaml.safe_load((ROOT / "CITATION.cff").read_text(encoding="utf-8"))
    assert data["cff-version"] == "1.2.0" and data["type"] == "software"
    assert data["title"] == "Scovant Core" and data["license"] == "Apache-2.0"
    assert data["version"] == scovant_core.__version__
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(data["date-released"]))
    assert data["url"].endswith("/open-source") and "github.com/Scovant/scovant-core" in data["repository-code"]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{scovant_core.__version__}] - {data['date-released']}" in changelog


def test_support_and_templates_exist_and_parse():
    assert (ROOT / "SUPPORT.md").read_text(encoding="utf-8").strip()
    assert (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").strip().startswith("*")
    for name in ("bug_report", "check_proposal", "false_positive"):
        data = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / f"{name}.yml").read_text(encoding="utf-8"))
        assert data["name"] and data["body"], name
    cfg = yaml.safe_load((ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8"))
    assert cfg["blank_issues_enabled"] is False and any("SECURITY" in c["url"] or "security" in c["name"].lower() for c in cfg["contact_links"])
    assert "## " in (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
