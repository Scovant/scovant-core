from __future__ import annotations

from scovant_core.engine import scan
from scovant_core.report.markdown import render_markdown
from tests.conftest import FIXTURES, FixtureTransport


def _report(site="commerce-bad", experimental=False):
    from scovant_core.context import ScanOptions

    return scan(
        "https://example.com/",
        ScanOptions(experimental=experimental),
        transport=FixtureTransport(FIXTURES / "sites" / site),
        clock=lambda: "2026-09-04T00:00:00Z",
        scan_id="md",
    )


def test_markdown_header_and_sections():
    md = render_markdown(_report())
    assert md.startswith("# Scovant Core — https://example.com/")
    for h in ("## Score", "## Categories", "## Findings", "## Not tested by Scovant Core", "## Provenance"):
        assert h in md
    assert md.rstrip().endswith("utm_medium=cli&utm_campaign=oss)")


def test_markdown_findings_grouped_with_details_evidence():
    md = render_markdown(_report())
    assert md.index("### FAIL") < md.index("### WARN") < md.index("### PASS")
    assert "<details><summary>evidence</summary>" in md and "```json" in md


def test_markdown_experimental_notice_when_all_na():
    md = render_markdown(_report("api-good"))
    assert (
        "Experimental checks: not scored (run with --experimental)" in md
        or "## Experimental (not scored)" in md
    )


def test_markdown_utm_medium_plumbing():
    assert "utm_medium=github" in render_markdown(_report(), utm_medium="github")


def test_markdown_never_contains_target_in_cta():
    md = render_markdown(_report())
    cta = md.rstrip().splitlines()[-1]
    assert "example.com" not in cta


def _counted(md: str) -> dict[str, int]:
    """The header count line, parsed: `45 checks: 37 PASS, 0 WARN, ...`."""
    line = next(ln for ln in md.splitlines() if " checks: " in ln)
    head, rest = line.split(" checks: ")
    counts = {}
    for part in rest.split(", "):
        n, label = part.split(" ", 1)
        counts[label] = int(n)
    counts["TOTAL"] = int(head)
    return counts


def _listed_ids(md: str) -> set[str]:
    import re

    body = md.split("## Findings", 1)[1].split("## Not tested by", 1)[0]
    return set(re.findall(r"CORE-[A-Z]+-\d+", body))


def test_every_counted_check_is_actually_listed_in_the_document():
    """The header counts all 45 checks; the status sections list only the
    scored ones. Experimental findings must therefore be accounted for in
    the experimental section — INCLUDING the `N/A` ones, which used to be
    counted in the header and appear nowhere in the body (three unexplained
    checks in the flagship published example report)."""
    for site in ("commerce-good", "commerce-bad", "api-good", "saas-mixed"):
        md = render_markdown(_report(site))
        assert len(_listed_ids(md)) == _counted(md)["TOTAL"], site
