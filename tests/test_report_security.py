"""Agentic Security & Trust report section — text/markdown/html/json all
carry the same security block off the report, disclaimer and
per-finding detail, and no renderer is ever allowed to claim a security
verdict."""
from __future__ import annotations

import json

from scovant_core.engine import scan
from scovant_core.models import SecuritySummary
from scovant_core.report._common import SECURITY_DISCLAIMER
from scovant_core.report.html import render_html
from scovant_core.report.json import render_json
from scovant_core.report.markdown import render_markdown
from scovant_core.report.text import render_text
from tests.conftest import FIXTURES, FixtureTransport

CLOCK = lambda: "2026-09-16T00:00:00Z"  # noqa: E731
BANNED = ("your website is secure", "no vulnerabilities", "oauth is secure", "cannot be exploited")


def _report(site="security-bad"):
    return scan("https://example.com/", transport=FixtureTransport(FIXTURES / "sites" / site), clock=CLOCK, scan_id="local-test")


def test_text_has_security_section_and_not_tested_lines():
    t = render_text(_report())
    assert "AGENTIC SECURITY & TRUST" in t and "PASSIVE SIGNALS ONLY" in t
    for name in ("Observed authorization", "Verified agent identity", "Prompt-injection resilience", "Tool invocation safety"):
        assert f"{name}" in t and "NOT TESTED" in t
    assert SECURITY_DISCLAIMER in t
    assert "[security]" in t  # tagged in Top findings


def test_markdown_and_html_carry_section_cards_and_disclaimer():
    r = _report()
    md, html = render_markdown(r), render_html(r)
    assert "## Agentic Security & Trust" in md and SECURITY_DISCLAIMER in md and "SEC-WEB-001" in md
    assert "Agentic Security &amp; Trust" in html and SECURITY_DISCLAIMER in html and "PASSIVE SIGNALS ONLY" in html


def test_json_security_block_and_fields():
    d = json.loads(render_json(_report()))
    assert d["schema_version"] == "1.1" and d["security"]["scored"] is False
    assert set(d["categories"]) == {"access", "machine", "interfaces", "trust", "operability"}
    f = next(x for x in d["findings"] if x["id"] == "CORE-SECURITY-001")
    assert f["family_id"] == "SEC-WEB-001" and f["verification_mode"] == "PASSIVE_OBSERVED" and f["fix_owner"]


def test_renderers_never_claim_security():
    for site in ("security-good", "security-bad"):
        r = _report(site)
        for out in (render_text(r), render_markdown(r), render_html(r)):
            low = out.lower()
            assert not any(b in low for b in BANNED), site


def test_security_good_has_no_open_findings():
    """The good fixture is a control: every SECURITY check PASSes/NAs on
    it, so the section renders but the finding cards are empty."""
    r = _report("security-good")
    sec = [f for f in r.findings if f.category.value == "security"]
    assert sec and all(f.status.value in ("PASS", "N/A") for f in sec)


def test_default_security_summary_is_disclosed_as_not_measured():
    """A pre-0.4.0 schema-1.0 report, re-rendered, round-trips `security`
    through `SecuritySummary`'s own empty defaults — `findings_by_severity`
    and `by_domain` both `{}`. That must read as "not measured", never as
    "Critical 0" — a real scan always carries a full 5-key severity dict
    (see `security_rows`'s own docstring)."""
    r = _report().model_copy(update={"security": SecuritySummary()})
    for out in (render_text(r), render_markdown(r), render_html(r)):
        assert "not measured" in out
        assert "Critical 0" not in out and "Critical</td><td>0" not in out


def test_excluding_security_renders_not_measured_not_zero_counts(monkeypatch):
    """`--exclude security` means no SECURITY check ran — the section must
    say so. A zero-filled severity dict would render "Critical 0", i.e. a
    clean bill of health for a domain that was never looked at."""
    from scovant_core.checks.access import core_access_006
    from scovant_core.context import ScanOptions
    from scovant_core.engine import scan
    from scovant_core.gatherers import security_txt
    from tests.conftest import FIXTURES, FixtureTransport
    from tests.test_golden import CLOCK, FROZEN_TODAY

    monkeypatch.setattr(core_access_006, "today", lambda: FROZEN_TODAY)
    monkeypatch.setattr(security_txt, "today", lambda: FROZEN_TODAY)
    r = scan("https://example.com/", ScanOptions(exclude=("security",)),
             transport=FixtureTransport(FIXTURES / "sites" / "commerce-good"), clock=CLOCK, scan_id="x")
    assert r.security.findings_by_severity == {} and r.security.by_domain == {}
    for out in (render_text(r), render_markdown(r), render_html(r)):
        assert "not measured" in out
        assert "Critical 0" not in out and "Critical</td><td>0" not in out
