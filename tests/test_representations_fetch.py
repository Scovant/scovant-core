"""scovant_core.representations.fetch — fetch-agnostic gathering + verdicts."""
from scovant_core.representations.fetch import (
    REPR_BODY_CAP,
    fetch_representations,
    mirror_url,
    public_fetch_meta,
    variant_verdict,
)

PAGE = "https://shop.test/p/widget"
HTML = ('<html><head><link rel="canonical" href="https://shop.test/p/widget"></head><body><main>'
        '<h1>Blue Widget</h1><p>$89.99</p><a href="/p/widget/reviews">r</a></main></body></html>')
MD = "# Blue Widget\n\n$89.99\n\n[r](/p/widget/reviews) https://shop.test/p/widget\n"


def _f(body, *, status=200, ctype="text/markdown", final=PAGE, pref=None, truncated=False, error=None):
    return {"status": status, "content_type": ctype, "vary": "Accept", "preference_applied": pref,
            "bytes": len(body or ""), "latency_ms": 12, "truncated": truncated, "final_url": final,
            "body": body, "error": error}


HTML_F = _f(HTML, ctype="text/html; charset=utf-8")


def test_mirror_url():
    assert mirror_url("https://a.test/") == "https://a.test/index.md"
    assert mirror_url("https://a.test") == "https://a.test/index.md"
    assert mirror_url("https://a.test/p/widget/") == "https://a.test/p/widget.md"
    assert mirror_url("https://a.test/p/widget?x=1#y") == "https://a.test/p/widget.md"


def test_fetch_sends_the_four_requests_with_their_headers():
    seen = []

    def fetch(url, headers):
        seen.append((url, headers))
        return _f(MD)
    out = fetch_representations(fetch, PAGE)
    assert set(out) == {"html", "markdown", "mirror", "consolidated"}
    assert seen[0][0] == PAGE and "markdown" not in seen[0][1].get("Accept", "")
    assert seen[1] == (PAGE, {"Accept": "text/markdown"})
    assert seen[2][0] == "https://shop.test/p/widget.md"
    assert seen[3][1] == {"Accept": "text/markdown;q=0.9, text/html;q=0.8", "Prefer": "return=consolidated"}


def test_equivalent_markdown_passes():
    v = variant_verdict(HTML_F, _f(MD), variant="markdown", page_url=PAGE)
    assert v["status"] == "PASS" and v["compare"]["prices"]["missing"] == []


def test_soft_200_html_mirror_is_na():
    v = variant_verdict(HTML_F, _f(HTML, ctype="text/html"), variant="mirror", page_url=PAGE)
    assert (v["status"], v["reason"], v["compare"]) == ("NA", "served_as_html", None)


def test_markdown_body_under_html_content_type_is_compared_and_warns():
    v = variant_verdict(HTML_F, _f(MD, ctype="text/html"), variant="markdown", page_url=PAGE)
    assert v["status"] == "WARN" and v["reason"] == "content_type_mismatch"


def test_consolidated_html_without_preference_applied_is_na():
    v = variant_verdict(HTML_F, _f(HTML, ctype="text/html"), variant="consolidated", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "preference_not_applied")


def test_consolidated_html_with_preference_applied_is_compared_as_html():
    v = variant_verdict(HTML_F, _f(HTML, ctype="text/html", pref="return=consolidated"),
                        variant="consolidated", page_url=PAGE)
    assert v["status"] == "PASS"


def test_not_offered_and_cross_site_are_na():
    assert variant_verdict(HTML_F, _f("", status=404), variant="mirror", page_url=PAGE)["reason"] == "not_offered"
    v = variant_verdict(HTML_F, _f(MD, final="https://login.other.test/x"), variant="mirror", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "cross_site_redirect")


def test_www_variant_is_not_cross_site():
    v = variant_verdict(HTML_F, _f(MD, final="https://www.shop.test/p/widget.md"), variant="mirror", page_url=PAGE)
    assert v["status"] == "PASS"


def test_our_failures_are_not_measured():
    assert variant_verdict(HTML_F, _f(None, status=None, error="robots"), variant="markdown",
                           page_url=PAGE) == {"status": "NOT_MEASURED", "reason": "robots", "compare": None}
    bad_base = _f(None, status=None, error="timeout")
    assert variant_verdict(bad_base, _f(MD), variant="markdown", page_url=PAGE)["reason"] == "baseline_timeout"
    base_404 = _f("", status=404, ctype="text/html")
    assert variant_verdict(base_404, _f(MD), variant="markdown", page_url=PAGE)["reason"] == "baseline_status"


def test_truncated_or_undecodable_is_inconclusive():
    v = variant_verdict(HTML_F, _f(MD, truncated=True), variant="markdown", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("INCONCLUSIVE", "truncated")
    v = variant_verdict(HTML_F, _f(None, error="undecodable"), variant="markdown", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("INCONCLUSIVE", "undecodable")


def test_public_meta_drops_the_body():
    meta = public_fetch_meta(_f(MD))
    assert "body" not in meta and meta["bytes"] == len(MD)


def test_body_cap_is_2_mib():
    # Real documentation HTML runs 0.55-1.4 MB uncompressed; at 512 KiB a
    # fifth of all comparisons came back INCONCLUSIVE/truncated.
    assert REPR_BODY_CAP == 2 * 1024 * 1024


def test_cli_fetch_reads_up_to_the_body_cap():
    # The CLI gatherer's SecureClient applies its own per-kind read limit
    # first; a kind smaller than REPR_BODY_CAP would truncate before Cloud does.
    from types import SimpleNamespace

    from scovant_core.gatherers.representations import _fetcher
    from scovant_core.security.policy import SecurityPolicy

    kinds = []

    class _Client:
        def fetch(self, url, *, kind, headers=None):
            kinds.append(kind)
            return SimpleNamespace(text="x", status=200, content_type="text/html", headers={},
                                   bytes_len=1, elapsed_ms=1, truncated=False, final_url=url)

    _fetcher(_Client())(PAGE, {})
    assert kinds and SecurityPolicy().limit_for(kinds[0]) >= REPR_BODY_CAP


def test_markdown_mirror_with_leading_html_comment_is_compared():
    md = "<!-- source: https://shop.test/p/widget -->\n" + MD
    v = variant_verdict(HTML_F, _f(md, ctype="text/markdown"), variant="mirror", page_url=PAGE)
    assert v["status"] == "PASS" and v["compare"] is not None


def test_html_page_after_leading_comment_is_still_served_as_html():
    body = "<!-- x -->\n<!doctype html><html><body>hi</body></html>"
    v = variant_verdict(HTML_F, _f(body, ctype="text/markdown"), variant="mirror", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "served_as_html")


def test_nothing_to_compare_is_inconclusive():
    # Finding 2: no links, no entities, no price on the HTML side — every
    # sub-check is empty, so an empty Markdown must not read as PASS.
    shell = _f('<html><body><div id="root"></div></body></html>', ctype="text/html")
    v = variant_verdict(shell, _f(""), variant="markdown", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("INCONCLUSIVE", "nothing_to_compare")
    assert v["compare"] is not None


def test_page_with_only_a_heading_still_compares():
    page = _f("<html><body><main><h1>Hello</h1></main></body></html>", ctype="text/html")
    v = variant_verdict(page, _f("# Hello\n"), variant="markdown", page_url=PAGE)
    assert v["status"] == "PASS"


def test_truncated_baseline_with_html_soft_200_alternate_is_served_as_html():
    # Finding 3: the alternate's not-applicable checks come before truncation.
    big = _f(HTML, ctype="text/html", truncated=True)
    soft = _f("<!doctype html><html><body>shop</body></html>", ctype="text/html")
    v = variant_verdict(big, soft, variant="markdown", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "served_as_html")


def test_truncated_baseline_with_not_offered_or_unapplied_preference_is_na():
    big = _f(HTML, ctype="text/html", truncated=True)
    v = variant_verdict(big, _f("nope", status=404, ctype="text/html"), variant="mirror", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "not_offered")
    alt = _f(HTML, ctype="text/html; charset=utf-8", pref=None)
    v = variant_verdict(big, alt, variant="consolidated", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("NA", "preference_not_applied")


def test_truncated_baseline_with_real_markdown_is_inconclusive():
    big = _f(HTML, ctype="text/html", truncated=True)
    v = variant_verdict(big, _f(MD), variant="markdown", page_url=PAGE)
    assert (v["status"], v["reason"]) == ("INCONCLUSIVE", "truncated")


def test_soft_time_limit_propagates_out_of_fetch_representations():
    # Finding 4: the host's soft time limit must not be swallowed as fetch_failed.
    import pytest

    from scovant_core.compat import SoftTimeLimitExceeded

    def fetch(url, headers):
        raise SoftTimeLimitExceeded()
    with pytest.raises(SoftTimeLimitExceeded):
        fetch_representations(fetch, PAGE)


def test_other_fetcher_exceptions_are_still_fetch_failed():
    def fetch(url, headers):
        raise RuntimeError("boom")
    out = fetch_representations(fetch, PAGE)
    assert {v["error"] for v in out.values()} == {"fetch_failed"}
