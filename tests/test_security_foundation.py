"""Foundation for the Agentic Security & Trust category: the SECURITY
category exists, is never scored, and its findings roll up into a separate
security summary block on the report. The SEC-WEB and SEC-TXT checks now
exist (checks/security/web.py); this file covers only the category-wide
contract every SECURITY check must satisfy (never scored, family/domain/
owner/mode/tags declared) — each family's own individual behavior is
covered by its own test module instead."""

from __future__ import annotations

from scovant_core.checks.base import CoreCheck
from scovant_core.checks.registry import CHECKS
from scovant_core.models import (
    REPORT_SCHEMA_VERSION,
    VERIFICATION_MODES,
    Category,
    CheckResult,
    CheckStatus,
    Confidence,
    SecuritySummary,
    Severity,
)
from scovant_core.scoring import CATEGORY_WEIGHTS, SCORED_CATEGORIES, score_results
from scovant_core.security_summary import SECURITY_NOT_TESTED, build_security_summary


def _r(id_, cat, status, severity=Severity.MEDIUM, experimental=False, **kw):
    return CheckResult(
        id=id_,
        title=id_,
        category=cat,
        status=status,
        severity=severity,
        confidence=Confidence.HIGH,
        weight=1,
        summary="s",
        experimental=experimental,
        **kw,
    )


def test_security_category_exists_and_is_not_scored():
    assert Category.SECURITY.value == "security"
    assert Category.SECURITY not in SCORED_CATEGORIES
    assert set(CATEGORY_WEIGHTS) == {c.value for c in SCORED_CATEGORIES}
    assert "security" not in CATEGORY_WEIGHTS


def test_schema_version_is_1_1():
    assert REPORT_SCHEMA_VERSION == "1.1"


def test_security_results_never_enter_the_score():
    base = [_r("CORE-ACCESS-001", Category.ACCESS, CheckStatus.PASS)]
    with_sec = base + [
        _r("CORE-SECURITY-001", Category.SECURITY, CheckStatus.FAIL, Severity.CRITICAL)
    ]
    s1, c1 = score_results(base)
    s2, c2 = score_results(with_sec)
    assert (s1.value, s1.coverage, s1.status) == (s2.value, s2.coverage, s2.status)
    assert set(c2) == {c.value for c in SCORED_CATEGORIES}


def test_check_result_new_fields_default():
    r = _r("CORE-ACCESS-001", Category.ACCESS, CheckStatus.PASS)
    assert r.family_id == "" and r.verification_mode == "PASSIVE_OBSERVED"
    assert r.security_domain == "" and r.fix_owner == "" and r.security_tags == []


def test_verification_mode_vocabulary():
    assert VERIFICATION_MODES == (
        "DECLARED",
        "PASSIVE_OBSERVED",
        "ACTIVE_SAFE",
        "SYNTHETIC_AUTHORIZED",
    )
    for c in CHECKS:
        assert c.verification_mode in VERIFICATION_MODES[:2], c.id


def test_build_security_summary_counts_fail_and_warn_only():
    fs = [
        _r(
            "CORE-SECURITY-001",
            Category.SECURITY,
            CheckStatus.FAIL,
            Severity.HIGH,
            security_domain="web_baseline",
        ),
        _r(
            "CORE-SECURITY-002",
            Category.SECURITY,
            CheckStatus.WARN,
            Severity.LOW,
            security_domain="web_baseline",
        ),
        _r(
            "CORE-SECURITY-007",
            Category.SECURITY,
            CheckStatus.PASS,
            Severity.INFO,
            security_domain="data_exposure",
        ),
        _r(
            "CORE-SECURITY-011",
            Category.SECURITY,
            CheckStatus.NA,
            Severity.INFO,
            security_domain="prompt_surface",
        ),
        _r("CORE-ACCESS-001", Category.ACCESS, CheckStatus.FAIL, Severity.CRITICAL),
    ]
    s = build_security_summary(fs)
    assert isinstance(s, SecuritySummary)
    assert s.scored is False and s.label == "PASSIVE SIGNALS ONLY"
    assert s.findings_by_severity == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert s.by_domain["web_baseline"] == {"PASS": 0, "WARN": 1, "FAIL": 1, "N/A": 0, "ERROR": 0}
    assert s.by_domain["prompt_surface"]["N/A"] == 1
    assert s.not_tested == SECURITY_NOT_TESTED
    assert s.redaction_applied is False


def test_build_security_summary_flags_redaction():
    f = _r(
        "CORE-SECURITY-007",
        Category.SECURITY,
        CheckStatus.FAIL,
        Severity.HIGH,
        security_domain="data_exposure",
        evidence={"hits": [{"redacted": "abcd…wxyz"}]},
    )
    assert build_security_summary([f]).redaction_applied is True


def test_core_check_copies_security_fields_into_result():
    class Probe(CoreCheck):
        id = "CORE-SECURITY-099"
        title = "probe"
        category = Category.SECURITY
        family_id = "SEC-WEB-099"
        verification_mode = "DECLARED"
        security_domain = "web_baseline"
        fix_owner = "edge_cdn"
        security_tags = ("agentic-security",)

        def evaluate(self, store, ctx):
            return self.result(CheckStatus.PASS, "ok")

    r = Probe().result(CheckStatus.PASS, "ok")
    assert (r.family_id, r.verification_mode, r.security_domain, r.fix_owner, r.security_tags) == (
        "SEC-WEB-099",
        "DECLARED",
        "web_baseline",
        "edge_cdn",
        ["agentic-security"],
    )


# Derived from each check's evidence source (module docstring + `store.get(...)`
# calls): DECLARED = the check's evidence IS a document/header the
# site itself published (robots.txt, sitemap, llms.txt, security.txt, OAuth
# discovery metadata, MCP discovery, OpenAPI spec, a UCP profile, an agent
# discovery surface, policy-page metadata) and nothing else. A check that
# also reads an observed source (pages/http/forms/contact/machine_links/
# soft_404/page_metrics/reference_integrity) is PASSIVE_OBSERVED even if one
# of its inputs is a declared document.
DECLARED_READINESS = {
    # robots.txt-only: availability/syntax (002), per-crawler policy (003,
    # 004), Content-Signal directive (010) — all read robots.txt alone.
    "CORE-ACCESS-002", "CORE-ACCESS-003", "CORE-ACCESS-004", "CORE-ACCESS-010",
    # sitemap.xml-only: availability (005), freshness/lastmod (006).
    "CORE-ACCESS-005", "CORE-ACCESS-006",
    # llms.txt-only (009); llms.txt + robots.txt, both declared docs (011).
    "CORE-ACCESS-009", "CORE-ACCESS-011",
    # MCP discovery document only (both server-presence and per-server
    # declaration-quality read `mcp_discovery` alone).
    "CORE-INTERFACE-001", "CORE-INTERFACE-002",
    # OpenAPI spec only — a formal API declaration the site publishes,
    # same standing as mcp_discovery.
    "CORE-INTERFACE-005",
    # OAuth discovery metadata only (RFC 8414 / RFC 9728, both unauthenticated
    # reads of a published metadata document).
    "CORE-INTERFACE-006", "CORE-INTERFACE-007",
    # UCP profile document only.
    "CORE-INTERFACE-008",
    # Agent discovery surface (llms.txt/agents.txt/mcp.json-family) only.
    "CORE-INTERFACE-009",
    # policy_pages metadata only (shipping/returns/privacy/terms).
    "CORE-TRUST-002", "CORE-TRUST-003", "CORE-TRUST-004", "CORE-TRUST-005",
    # security.txt (RFC 9116) only.
    "CORE-TRUST-006",
}


def test_every_readiness_check_declares_verification_mode_explicitly():
    for c in CHECKS:
        if c.category == Category.SECURITY:
            continue
        check_id = c.id
        assert "verification_mode" in vars(type(c)), f"{check_id} does not declare verification_mode explicitly"
        expected = "DECLARED" if check_id in DECLARED_READINESS else "PASSIVE_OBSERVED"
        assert c.verification_mode == expected, check_id
