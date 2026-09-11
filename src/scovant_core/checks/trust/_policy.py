"""Shared verdict logic for the policy-page trust checks (CORE-TRUST-002
shipping / -003 returns / -004 privacy / -005 terms): each reads one
`policy_pages` record and reduces it to a `(status, summary, evidence,
confidence)` quadruple by the same rules, differing only in what happens
when no link was ever found (`missing_status`) — WARN for shipping/returns/
terms, FAIL for privacy (a public site with no privacy page at all is a
real defect, not merely an omission the way a missing shipping page might
be).

`served_as_html` is deliberately never consulted here: unlike robots.txt/a
sitemap/llms.txt, a policy page genuinely IS an HTML document — there is no
soft-404 catch-all to distinguish it from (see `gatherers/policy_pages.py`'s
own docstring). It stays in the evidence for transparency only.
"""
from __future__ import annotations

from scovant_core.checks._truncation import record_truncation, truncated_confidence
from scovant_core.models import CheckStatus, Confidence

MIN_TEXT_CHARS = 200


def policy_verdict(
    page: dict | None, *, missing_status: CheckStatus, label: str = "policy page"
) -> tuple[CheckStatus, str, dict, Confidence]:
    """`page` is one `policy_pages["pages"][kind]` record, or `None` when no
    link to it was ever discovered from the entry page. `label` names the
    kind in prose (e.g. "shipping policy page") for the summary text."""
    if page is None:
        # Nothing was ever fetched here — there is no document whose
        # truncation could be at issue.
        return missing_status, f"No {label} was found linked from the entry page.", {}, Confidence.HIGH

    evidence = {
        "url": page["url"],
        "status": page["status"],
        "text_chars": page["text_chars"],
        "served_as_html": page["served_as_html"],
    }
    # `page` is the ONE document every branch below is drawn from — its own
    # per-page `truncated` flag (not `policy_pages`' record-level OR across
    # every fetched policy page, which folds shipping/returns/privacy/terms/
    # pricing into one boolean — see FOLDED_RECORD_NAMES in
    # test_truncation_document_labels.py). `label` is a caller-supplied
    # runtime string here, so it cannot be passed as `document=` (the AST
    # audit requires a literal); the generic wording is used instead — still
    # honest, just less specific than the per-check checks manage elsewhere.
    note, truncated = record_truncation(page, evidence)
    conf = truncated_confidence(truncated)

    if page["status"] is None:
        # A `FetchError` page dict always carries `truncated: False` (see
        # `gatherers/policy_pages.py`) — the read failed outright, nothing
        # was cut off mid-body — so `note` is always empty here in
        # practice; included for uniformity with every other branch.
        return CheckStatus.ERROR, f"The {label} could not be read." + note, evidence, conf

    if page["status"] >= 400:
        return CheckStatus.WARN, f"The {label} link is broken (HTTP {page['status']})." + note, evidence, conf

    if page["text_chars"] < MIN_TEXT_CHARS:
        return (
            CheckStatus.WARN,
            f"A {label} was found but has too little text ({page['text_chars']} chars) to be a real policy document." + note,
            evidence, conf,
        )

    return CheckStatus.PASS, f"A {label} was found with substantive content." + note, evidence, conf
