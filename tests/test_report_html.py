import re

from scovant_core.report.html import render_html
from tests.test_report_markdown import _report

SECTION_IDS = ("summary", "score", "categories", "findings", "evidence", "remediation",
               "limitations", "not-tested", "cloud-comparison", "methodology", "provenance")


def test_html_has_every_section_in_spec_order():
    html = render_html(_report())
    positions = [html.index(f'id="{s}"') for s in SECTION_IDS]
    assert positions == sorted(positions)


def test_html_is_self_contained():
    html = render_html(_report())
    assert "<script" not in html.lower() and "<form" not in html.lower() and "<img" not in html.lower()
    for url in re.findall(r'(?:href|src)="([^"]+)"', html):
        assert url.startswith("#") or url.startswith("https://scovant.com/scan?utm_source=scovant-core") \
            or url.startswith("https://github.com/Scovant/scovant-core"), url


def test_html_escapes_site_supplied_strings():
    r = _report()
    hostile = '<script>alert(1)</script>"><img src=x onerror=alert(1)>'
    r.findings[0] = r.findings[0].model_copy(update={"summary": hostile, "evidence": {"title": hostile}})
    html = render_html(r)
    assert "<script>alert" not in html and "&lt;script&gt;alert" in html and "onerror=" not in html.replace("onerror=alert(1)&gt;", "")


def test_html_size_bound_on_largest_golden():
    for site in ("commerce-good", "commerce-bad", "api-good", "saas-mixed"):
        assert len(render_html(_report(site)).encode()) < 512 * 1024


def test_html_utm_medium():
    assert "utm_medium=html" in render_html(_report()) and "utm_medium=mcp" in render_html(_report(), utm_medium="mcp")


def test_limitations_section_excludes_unscored_experimental_findings():
    """The Limitations section applies the same `(experimental and not
    scored)` exclusion as Evidence/Remediation: an experimental finding's
    limitations text must not appear unless it was actually scored
    (`--experimental`)."""
    unscored = render_html(_report("commerce-good", experimental=False))
    scored = render_html(_report("commerce-good", experimental=True))
    limitations_only = lambda html: html.split('id="limitations"', 1)[1].split('id="not-tested"', 1)[0]  # noqa: E731
    experimental_limitation_texts = [
        f.limitations
        for f in _report("commerce-good", experimental=True).findings
        if f.experimental and f.limitations
    ]
    assert experimental_limitation_texts, "fixture must carry an experimental finding with limitations text"
    for text in experimental_limitation_texts:
        assert text not in limitations_only(unscored)
        assert text in limitations_only(scored)
