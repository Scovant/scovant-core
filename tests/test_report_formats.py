"""Cross-format parity: the header/summary count in every renderer must
agree with what the body actually lists. `test_report_markdown.py` already
pins this for Markdown — the Markdown renderer already carries this fix —
and this file pins the same invariant for HTML and text, which carried the
identical split: an experimental `N/A` finding was counted in the summary
line but named nowhere in the body.

Note on scope: HTML's "Findings" table lists every finding for every
status, exactly like Markdown's — so the literal "every counted check is
individually named" invariant applies to it in full. `render_text` is, by
design, a compact CLI summary (category roll-up counts + capped Top
findings + the experimental block) that has never individually named
non-experimental PASS/WARN/FAIL/N-A findings — that is a pre-existing,
deliberate property of the format, not part of the counting split this fix
addresses. So text is pinned on the invariant that IS being fixed here
(every experimental N/A id, which the header counts, is named in the
experimental block) rather than on total listing completeness, which would
require redesigning `render_text` into a full findings dump — out of scope
for a presentation-parity fix, and narrower than that: only the missing ids
need to appear, as one compact line.
"""
from __future__ import annotations

import re

import pytest

from scovant_core.report._common import na_experimental
from scovant_core.report.html import render_html
from scovant_core.report.text import render_text


@pytest.mark.parametrize("site", ["commerce-good", "commerce-bad", "api-good", "saas-mixed"])
def test_html_summary_count_agrees_with_what_it_lists(site, load_expected):
    """HTML's Findings table lists every finding for every status (like
    Markdown's) — so, unlike text, full completeness is the right invariant
    here. The markdown renderer said 8 N/A while listing 5 — three checks
    unaccounted for in a published artefact; HTML carried the same split."""
    report = load_expected(site)
    out = render_html(report)
    listed = {f.id for f in report.findings if f.id in out}
    assert len(listed) == len(report.findings), (
        f"render_html lists {len(listed)} of {len(report.findings)} checks")


@pytest.mark.parametrize("site", ["commerce-good", "commerce-bad", "api-good", "saas-mixed"])
@pytest.mark.parametrize("renderer", [render_html, render_text])
def test_na_experimental_ids_are_named_by_a_dedicated_marker_not_incidental_prose(
    site, renderer, load_expected,
):
    """The actual counting split this fix addresses: the summary/header
    line counts every experimental `N/A` finding, but neither renderer
    named them anywhere. A naive substring search over the whole rendered
    output is not a safe test of that fix — it can pass for the wrong
    reason. That is not hypothetical: in `commerce-bad`, CORE-MACHINE-012's
    own (always-rendered) summary reads "...evaluated by
    CORE-MACHINE-004/005" — a live cross-reference to another finding's id
    inside ordinary rendered prose, unrelated to whether that id is ever
    accounted for as a check in its own right.

    So this test does not check presence anywhere in the document: it
    isolates the dedicated "N/A: ..." marker line each renderer now emits
    for experimental N/A findings (bounded by `\\b` so a longer id can
    never satisfy a shorter one) and asserts every such id appears THERE,
    word-for-word — tying the fix to its actual mechanism rather than to
    coincidental text elsewhere in the document.
    """
    report = load_expected(site)
    na_ids = {f.id for f in na_experimental(report.findings)}
    if not na_ids:
        pytest.skip(f"{site} has no experimental N/A findings to pin")
    out = renderer(report)
    marker = next(line for line in out.splitlines() if "N/A:" in line)
    for finding_id in na_ids:
        assert re.search(rf"\b{re.escape(finding_id)}\b", marker), (
            f"{renderer.__name__}/{site}: {finding_id} missing from the N/A marker line: {marker!r}")
