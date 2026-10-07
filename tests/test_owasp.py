"""OWASP Agentic Top 10 — a mapping, never a compliance claim."""
from __future__ import annotations

import pathlib

import pytest

import scovant_core.checks  # noqa: F401 — populates the registry
from scovant_core.checks.registry import CHECKS
from scovant_core.models import Category, CheckStatus
from scovant_core.owasp import (
    ASI_TITLES,
    RELATIONS,
    RULE_MAPPINGS,
    describe,
    entry,
    for_rule,
    parse_standards,
)
from scovant_core.rules.base import RULES

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_the_ten_categories_and_their_titles():
    assert list(ASI_TITLES) == [f"ASI{n:02d}" for n in range(1, 11)]
    assert ASI_TITLES["ASI03"] == "Identity & Privilege Abuse"


def test_a_result_carries_the_mapping_its_check_declares():
    for check in CHECKS:
        result = check.result(CheckStatus.FAIL, "s")
        assert result.owasp_agentic == parse_standards(check.standards), check.id


def test_every_security_check_that_declares_an_owasp_standard_is_mapped():
    declared = {c.id for c in CHECKS if c.category == Category.SECURITY
                and any(s.startswith("OWASP") for s in c.standards)}
    mapped = {c.id for c in CHECKS if parse_standards(c.standards)}
    assert declared == mapped and len(declared) == 8


def test_a_reference_that_is_not_owasp_is_not_a_mapping():
    assert parse_standards(("RFC 9116", "MDN:HTTPS")) == []


@pytest.mark.parametrize("bad", ["OWASP Agentic Top 10 2026: ASI11 (partial)",
                                 "OWASP Agentic Top 10 2026: ASI01",
                                 "OWASP Agentic Top 10 2026: ASI01 (compliant)"])
def test_an_unreadable_owasp_declaration_fails_loudly(bad):
    with pytest.raises(ValueError):
        parse_standards((bad,))


def test_rule_mappings_name_only_registered_rules_and_valid_entries():
    codes = {r.code for r in RULES}
    assert set(RULE_MAPPINGS) <= codes
    for code, maps in RULE_MAPPINGS.items():
        assert maps, code
        for asi, rel in maps:
            assert asi in ASI_TITLES and rel in RELATIONS, code
    assert for_rule("NOT-A-RULE") == []


def test_no_mapping_claims_more_than_partial():
    """A passive scan observes a signal relevant to a category, never the
    whole category — every mapping Core ships is PARTIAL."""
    rels = {e["relation"] for c in CHECKS for e in parse_standards(c.standards)}
    rels |= {rel for maps in RULE_MAPPINGS.values() for _, rel in maps}
    assert rels == {"PARTIAL"}


def test_security_md_rule_table_matches_the_mapping_both_ways():
    text = (ROOT / "docs/security.md").read_text(encoding="utf-8")
    section = text.split("#### Per-rule mapping", 1)[1]
    rows = {tuple(c.strip() for c in line.split("|")[1:-1])
            for line in section.splitlines()
            if line.startswith("| ") and not line.startswith(("| Rule", "|---"))}
    expected = {(code, asi, rel) for code, maps in RULE_MAPPINGS.items() for asi, rel in maps}
    assert rows == expected


def test_describe_reads_as_a_mapping_and_says_nothing_when_empty():
    assert describe([entry("ASI01", "PARTIAL")]) == "ASI01 Agent Goal Hijack (partial)"
    assert describe([]) == ""


def test_reports_label_the_mapping_and_never_claim_compliance():
    from scovant_core.report import html, markdown

    for module in (markdown, html):
        src = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert "not a compliance claim" in src
    for path in (ROOT / "src/scovant_core").rglob("*.py"):
        lowered = path.read_text(encoding="utf-8").lower()
        for banned in ("owasp compliant", "owasp-compliant", "owasp certified"):
            assert banned not in lowered, (path, banned)
