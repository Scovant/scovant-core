from __future__ import annotations

import datetime

import httpx

import scovant_core.gatherers._register  # noqa: F401 — registers pages/openapi/http/robots/... gatherers
from scovant_core.checks.access import core_access_006
from scovant_core.checks.access.core_access_001 import HttpsReachability
from scovant_core.checks.access.core_access_002 import RobotsTxtAvailability
from scovant_core.checks.access.core_access_003 import AiSearchCrawlerPolicy
from scovant_core.checks.access.core_access_004 import TrainingVsSearchSeparation
from scovant_core.checks.access.core_access_005 import SitemapAvailability
from scovant_core.checks.access.core_access_006 import SitemapFreshness
from scovant_core.checks.access.core_access_007 import CanonicalIntegrity
from scovant_core.checks.access.core_access_008 import Indexability
from scovant_core.checks.access.core_access_009 import LlmsTxtIntegrity
from scovant_core.checks.access.core_access_010 import ContentSignalDeclaration
from scovant_core.context import ScanContext, ScanOptions
from scovant_core.evidence import GATHERERS, EvidenceStore
from scovant_core.models import CheckStatus, Confidence
from scovant_core.profiles import apply_profile

from .conftest import make_client


def _scan(client, options: ScanOptions | None = None):
    ctx = ScanContext("https://example.com/", options or ScanOptions())
    store = EvidenceStore(client, ctx)
    apply_profile(ctx, store)
    return store, ctx


_DEFAULT_INDEX = (
    "<!doctype html><html><head><title>Test</title></head><body>"
    "<h1>Test</h1><p>Minimal page with enough visible text for the parser "
    "to treat this as real content rather than an empty shell.</p></body></html>"
)


def _site_handler(*, index_html: str | None = None, robots: str | None = None,
                   sitemap: str | None = None, llms: str | None = None,
                   extra: dict[str, tuple[int, str, str]] | None = None):
    """Build a MockTransport handler serving a synthetic example.com site.
    Any of robots/sitemap/llms left as None 404s (real absence); `extra`
    maps additional paths to (status, body, content_type)."""
    body_index = index_html if index_html is not None else _DEFAULT_INDEX
    extra = extra or {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=body_index.encode(), headers={"content-type": "text/html"})
        if path == "/robots.txt":
            if robots is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, content=robots.encode(), headers={"content-type": "text/plain"})
        if path == "/sitemap.xml":
            if sitemap is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, content=sitemap.encode(), headers={"content-type": "application/xml"})
        if path == "/llms.txt":
            if llms is None:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, content=llms.encode(), headers={"content-type": "text/plain"})
        if path in extra:
            status, extra_body, ctype = extra[path]
            return httpx.Response(status, content=extra_body.encode(), headers={"content-type": ctype})
        return httpx.Response(404, text="not found")

    return handler


def _raise_connect_error(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("simulated network failure", request=request)


def _robots_unreachable_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != "example.com":
        return httpx.Response(404, text="wrong host")
    if request.url.path == "/robots.txt":
        raise httpx.ConnectError("simulated network failure", request=request)
    if request.url.path == "/":
        return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


def _robots_served_as_html_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != "example.com":
        return httpx.Response(404, text="wrong host")
    if request.url.path == "/robots.txt":
        return httpx.Response(200, content=b"<html><body>Not Found</body></html>", headers={"content-type": "text/html"})
    if request.url.path == "/":
        return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


def _sitemap_503_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != "example.com":
        return httpx.Response(404, text="wrong host")
    if request.url.path in ("/sitemap.xml", "/sitemap_index.xml"):
        return httpx.Response(503, text="service unavailable")
    if request.url.path == "/":
        return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


def _sitemap_connect_error_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host != "example.com":
        return httpx.Response(404, text="wrong host")
    if request.url.path in ("/sitemap.xml", "/sitemap_index.xml"):
        raise httpx.ConnectError("simulated network failure", request=request)
    if request.url.path == "/":
        return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
    return httpx.Response(404, text="not found")


def _sitemap_entries(entries):
    def gatherer(client, ctx, store):
        return {"exists": True, "valid": True, "url": "https://example.com/sitemap.xml", "kind": "urlset",
                "entries": entries, "truncated": False, "parse_error": None}
    return gatherer


# ---------------------------------------------------------------------------
# 001 HTTPS reachability
# ---------------------------------------------------------------------------

def test_001_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = HttpsReachability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["redirect_count"] == 0


def test_001_warn_on_bad_redirect_chain(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = HttpsReachability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["redirect_count"] == 4


# ---------------------------------------------------------------------------
# 002 robots.txt availability and syntax
# ---------------------------------------------------------------------------

def test_002_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_002_fail_on_bad_general_disallow_all(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.FAIL


def test_002_error_when_robots_txt_gatherer_raises():
    def _boom(client, ctx, store):
        raise RuntimeError("boom")

    GATHERERS["robots_txt"] = _boom
    client = make_client(lambda r: httpx.Response(404))
    ctx = ScanContext("https://example.com/", ScanOptions())
    store = EvidenceStore(client, ctx)
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 003 AI search crawler policy
# ---------------------------------------------------------------------------

def test_003_pass_on_good_all_allowed(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert all(result.evidence["declared_policy"].values())


def test_003_fail_on_bad_all_disallowed(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert not any(result.evidence["declared_policy"].values())


# ---------------------------------------------------------------------------
# 004 training vs. search separation
# ---------------------------------------------------------------------------

def test_004_pass_on_good_explicit_separation(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = TrainingVsSearchSeparation().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["explicit_separation"] is True


def test_004_warn_on_bad(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = TrainingVsSearchSeparation().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["search_blocked"]


# ---------------------------------------------------------------------------
# 005 sitemap availability
# ---------------------------------------------------------------------------

def test_005_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["valid"] is True


def test_005_fail_on_bad_commerce_profile(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    assert ctx.profile == "commerce"
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["exists"] is False


# ---------------------------------------------------------------------------
# 006 sitemap freshness
# ---------------------------------------------------------------------------

def test_006_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_006_na_on_bad_no_sitemap(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.NA


# ---------------------------------------------------------------------------
# 007 canonical integrity
# ---------------------------------------------------------------------------

def test_007_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_007_fail_on_bad_offhost_canonical(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["canonical_url"] == "https://example.org/elsewhere"


# ---------------------------------------------------------------------------
# 008 indexability
# ---------------------------------------------------------------------------

def test_008_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = Indexability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_008_fail_on_bad_noindex(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = Indexability().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["robots_meta"] and "noindex" in result.evidence["robots_meta"].lower()


# ---------------------------------------------------------------------------
# 009 llms.txt integrity
# ---------------------------------------------------------------------------

def test_009_pass_on_good_all_refs_ok(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["references_checked"] == 2
    assert result.evidence["references_broken"] == []


def test_009_warn_on_bad_broken_reference(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["references_broken"]


def test_009_na_not_published_on_real_404():
    store, ctx = _scan(make_client(_site_handler()))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert result.evidence["http_status"] == 404


def test_009_error_when_llms_txt_unreadable_network_error():
    def _llms_unreachable(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path == "/llms.txt":
            raise httpx.ConnectError("simulated network failure", request=request)
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_llms_unreachable))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_009_error_when_llms_txt_server_errors():
    def _llms_500(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path == "/llms.txt":
            return httpx.Response(500, text="server error")
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_llms_500))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_009_error_when_llms_txt_forbidden():
    def _llms_403(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path == "/llms.txt":
            return httpx.Response(403, text="forbidden")
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(_llms_403))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# ---------------------------------------------------------------------------
# 010 Content-Signal declaration
# ---------------------------------------------------------------------------

def test_010_pass_on_good(fixture_site):
    store, ctx = _scan(fixture_site("commerce-good"))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_010_warn_on_bad_syntax_error(fixture_site):
    store, ctx = _scan(fixture_site("commerce-bad"))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["syntax_errors"]


def test_010_warn_on_conflicting_dimensions():
    robots = "User-agent: *\nDisallow:\n\nContent-Signal: search=no, ai-input=yes\n"
    store, ctx = _scan(make_client(_site_handler(robots=robots)))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["dimensions"]["search"] == "no"
    assert result.evidence["dimensions"]["ai-input"] == "yes"


def test_010_na_on_real_404_no_robots_txt():
    store, ctx = _scan(make_client(_site_handler()))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.NA


def test_010_error_when_robots_unreadable_network_error():
    store, ctx = _scan(make_client(_robots_unreachable_handler))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_010_error_when_robots_served_as_html():
    store, ctx = _scan(make_client(_robots_served_as_html_handler))
    result = ContentSignalDeclaration().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# ---------------------------------------------------------------------------
# Additional branch coverage — unreadable-document N/A invariant, remaining
# branches not exercised by the good/bad fixture pair alone.
# ---------------------------------------------------------------------------

# --- 002: robots.txt now routes ERROR classification through the shared
# `document_status` helper — a genuinely unreadable document (network
# failure, 5xx, 401/403) is ERROR, never WARN. Confirmed absence (a real
# 404/410) and a served-as-html catch-all keep their own WARN handling
# below: for robots.txt, absence itself is the finding (crawlers assume
# allow-all with no sitemap hint), not a data-quality gap.

def test_002_error_on_status_none():
    store, ctx = _scan(make_client(_robots_unreachable_handler))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] is None
    assert result.evidence["error"] is not None


def test_002_error_on_5xx():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path == "/robots.txt":
            return httpx.Response(500, text="server error")
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] == 500


def test_002_error_on_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path == "/robots.txt":
            return httpx.Response(403, text="forbidden")
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["status"] == 403


def test_002_warn_on_real_404_no_robots_txt():
    store, ctx = _scan(make_client(_site_handler()))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["status"] == 404


def test_002_warn_on_served_as_html():
    store, ctx = _scan(make_client(_robots_served_as_html_handler))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["served_as_html"] is True


def test_002_warn_on_unknown_directive():
    robots = "User-agent: *\nDisallow: /private/\n\nFoo-Bar: baz\n"
    store, ctx = _scan(make_client(_site_handler(robots=robots)))
    result = RobotsTxtAvailability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["unknown_directives"] == ["foo-bar"]


# --- 003/004: unreadable robots.txt must never yield a confident verdict.

def test_003_error_when_robots_unreadable_network_error():
    store, ctx = _scan(make_client(_robots_unreachable_handler))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_003_error_when_robots_served_as_html():
    store, ctx = _scan(make_client(_robots_served_as_html_handler))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_003_warn_on_partial_disallow():
    robots = "User-agent: OAI-SearchBot\nDisallow: /\n"
    store, ctx = _scan(make_client(_site_handler(robots=robots)))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["declared_policy"]["OAI-SearchBot"] is False
    assert result.evidence["declared_policy"]["Googlebot"] is True


def test_003_absent_path_evidence_is_not_a_parsed_policy():
    # robots=None → a real 404, not an unreadable document.
    store, ctx = _scan(make_client(_site_handler()))
    result = AiSearchCrawlerPolicy().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["declared_policy"] is None
    assert result.evidence["robots_present"] is False


def test_004_error_when_robots_unreadable_network_error():
    store, ctx = _scan(make_client(_robots_unreachable_handler))
    result = TrainingVsSearchSeparation().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


def test_004_error_when_robots_served_as_html():
    store, ctx = _scan(make_client(_robots_served_as_html_handler))
    result = TrainingVsSearchSeparation().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# --- 005: non-commerce/content profile downgrades a missing sitemap to WARN.

def test_005_warn_on_non_commerce_profile_no_sitemap():
    store, ctx = _scan(make_client(_site_handler()), options=ScanOptions(profile="saas"))
    assert ctx.profile == "saas"
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["exists"] is False


# --- 005: a sitemap that could not be READ (5xx/network error) must never
# be reported as a confident "no sitemap found" FAIL/WARN.

def test_005_error_on_sitemap_503():
    store, ctx = _scan(make_client(_sitemap_503_handler), options=ScanOptions(profile="commerce"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["probe_status"] == 503
    assert "could not be" in result.summary.lower()


def test_005_error_on_sitemap_connect_error():
    store, ctx = _scan(make_client(_sitemap_connect_error_handler), options=ScanOptions(profile="commerce"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["probe_error"] is not None
    assert "could not be" in result.summary.lower()


def test_005_error_on_sitemap_403():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "example.com":
            return httpx.Response(404, text="wrong host")
        if request.url.path in ("/sitemap.xml", "/sitemap_index.xml"):
            return httpx.Response(403, text="forbidden")
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), options=ScanOptions(profile="commerce"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["probe_status"] == 403
    assert "could not be" in result.summary.lower()


def test_005_fail_on_real_404_commerce():
    store, ctx = _scan(make_client(_site_handler()), options=ScanOptions(profile="commerce"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["probe_status"] == 404
    assert result.evidence["probe_error"] is None


# --- 006: date-branch coverage via a frozen `today` and a fake sitemap_urls.

def test_006_pass_when_no_lastmod_declared(monkeypatch):
    monkeypatch.setattr(core_access_006, "today", lambda: datetime.date(2026, 9, 4))
    GATHERERS["sitemap_urls"] = _sitemap_entries([
        {"loc": "https://example.com/a", "lastmod": None},
        {"loc": "https://example.com/b", "lastmod": None},
    ])
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["dated_entry_count"] == 0


def test_006_warn_on_future_lastmod(monkeypatch):
    monkeypatch.setattr(core_access_006, "today", lambda: datetime.date(2026, 9, 4))
    GATHERERS["sitemap_urls"] = _sitemap_entries([
        {"loc": "https://example.com/a", "lastmod": "2026-12-25"},
    ])
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "future" in result.summary.lower()


def test_006_warn_on_uniform_lastmod_across_five_or_more(monkeypatch):
    monkeypatch.setattr(core_access_006, "today", lambda: datetime.date(2026, 9, 4))
    entries = [{"loc": f"https://example.com/{i}", "lastmod": "2026-01-01"} for i in range(5)]
    GATHERERS["sitemap_urls"] = _sitemap_entries(entries)
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "same lastmod date" in result.summary.lower()


def test_006_warn_on_stale_sitemap(monkeypatch):
    monkeypatch.setattr(core_access_006, "today", lambda: datetime.date(2026, 9, 4))
    GATHERERS["sitemap_urls"] = _sitemap_entries([
        {"loc": "https://example.com/a", "lastmod": "2020-01-01"},
    ])
    store, ctx = _scan(make_client(lambda r: httpx.Response(404)))
    result = SitemapFreshness().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert "days old" in result.summary.lower()


# --- 007: absent canonical / off-host same-path already covered by the
# fixture pair; add same-host-different-path (404 → FAIL, 200 → WARN) and
# the entry-unparsed → ERROR path (product spec §6: unreadable, not N/A).

def test_007_warn_when_canonical_absent():
    store, ctx = _scan(make_client(_site_handler()))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["canonical_url"] is None


def test_007_fail_when_canonical_same_host_404():
    index = _DEFAULT_INDEX.replace(
        "<head>", '<head><link rel="canonical" href="https://example.com/missing">'
    )
    store, ctx = _scan(make_client(_site_handler(index_html=index)))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.FAIL
    assert result.evidence["canonical_ref_status"] == 404


def test_007_warn_when_canonical_same_host_different_path_resolves():
    index = _DEFAULT_INDEX.replace(
        "<head>", '<head><link rel="canonical" href="https://example.com/other">'
    )
    store, ctx = _scan(make_client(_site_handler(
        index_html=index, extra={"/other": (200, "<html><body>ok</body></html>", "text/html")},
    )))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["canonical_ref_status"] == 200
    assert "redirected" not in result.evidence


def test_007_error_when_entry_page_unreadable():
    store, ctx = _scan(make_client(_raise_connect_error))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# --- 008: entry-unparsed → ERROR path (product spec §6: unreadable, not N/A).

def test_008_error_when_entry_page_unreadable():
    store, ctx = _scan(make_client(_raise_connect_error))
    result = Indexability().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert "could not be" in result.summary.lower()


# --- 009: present-but-not-well-formed llms.txt (no Markdown links at all).

def test_009_warn_on_not_well_formed():
    llms = "# Notes\n\nJust some prose here, no markdown links at all.\n"
    store, ctx = _scan(make_client(_site_handler(llms=llms)))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.WARN
    assert result.evidence["valid"] is False


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_has_the_access_ten():
    from scovant_core.checks.registry import CHECKS

    ids = {c.id for c in CHECKS}
    expected = {f"CORE-ACCESS-{n:03d}" for n in range(1, 11)}
    assert expected <= ids


# ---------------------------------------------------------------------------
# Soft-200 catch-all: a 200 HTML page is an ABSENT document, not a broken one
# ---------------------------------------------------------------------------

_CATCH_ALL_PAGE = (
    "<!doctype html><html><head><title>Not found</title></head><body>"
    "<h1>Page not found</h1><p>Try the homepage instead of this soft-404 page.</p>"
    "</body></html>"
)


def _catch_all_handler(request: httpx.Request) -> httpx.Response:
    """Every path answers 200 with the same HTML page — the catch-all router /
    soft-404 template shape that makes a site look like it publishes every
    machine document it does not actually publish."""
    if request.url.host != "example.com":
        return httpx.Response(404, text="wrong host")
    return httpx.Response(200, content=_CATCH_ALL_PAGE.encode(), headers={"content-type": "text/html"})


def test_005_catch_all_html_sitemap_reads_as_absent_not_invalid():
    store, ctx = _scan(make_client(_catch_all_handler), ScanOptions(profile="commerce"))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.FAIL  # commerce profile: absence is a FAIL
    assert "No sitemap was found" in result.summary
    assert result.evidence["served_as_html"] is True
    assert result.evidence["exists"] is False


def test_009_catch_all_html_llms_txt_is_not_published():
    store, ctx = _scan(make_client(_catch_all_handler))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.NA
    assert "No llms.txt is published" in result.summary


def test_009_all_references_unresolved_is_an_error_not_a_warning():
    """Every llms.txt reference failed OUR fetch — nothing about the site was
    established, so the check reports ERROR rather than accusing the site of
    publishing dead links."""
    llms = "# Site\n\n> summary\n\n## Docs\n- [A](https://example.com/a)\n- [B](https://example.com/b)\n"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/plain"})
        if path in ("/a", "/b"):
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.ERROR
    assert result.evidence["references_broken"] == []
    assert len(result.evidence["references_unresolved"]) == 2


def test_009_one_unresolved_reference_alongside_a_live_one_still_passes():
    llms = "# Site\n\n> summary\n\n## Docs\n- [A](https://example.com/a)\n- [B](https://example.com/b)\n"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/plain"})
        if path == "/a":
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})
        if path == "/b":
            raise httpx.ConnectTimeout("simulated network failure", request=request)
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = LlmsTxtIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["references_broken"] == []
    assert result.evidence["references_unresolved"] == ["https://example.com/b"]


# ---------------------------------------------------------------------------
# Redirect-following probes + bare-origin canonical
# ---------------------------------------------------------------------------

def test_005_sitemap_declared_behind_a_redirect_is_found_and_valid():
    """robots.txt declares /sitemap.xml, which 301s to /sitemap-1.xml. The
    probe follows redirects through the guarded client, so the sitemap is
    found — before, a declared-but-redirected sitemap read as absent."""
    sitemap = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.com/</loc></url></urlset>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/robots.txt":
            return httpx.Response(
                200, text="User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml\n",
                headers={"content-type": "text/plain"},
            )
        if path == "/sitemap.xml":
            return httpx.Response(301, headers={"location": "https://example.com/sitemap-1.xml"})
        if path == "/sitemap-1.xml":
            return httpx.Response(200, text=sitemap, headers={"content-type": "application/xml"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert result.evidence["valid"] is True


def test_007_bare_origin_canonical_matches_a_trailing_slash_entry_url():
    """`https://example.com` and `https://example.com/` are the same resource;
    a canonical written without the path must not read as a differing one."""
    body = (
        '<!doctype html><html><head><title>t</title>'
        '<link rel="canonical" href="https://example.com">'
        "</head><body><h1>t</h1><p>enough visible text content for the parser to treat as real.</p>"
        "</body></html>"
    )
    store, ctx = _scan(make_client(_site_handler(index_html=body)))
    result = CanonicalIntegrity().run(store, ctx)
    assert result.status == CheckStatus.PASS
    assert "matches the entry URL" in result.summary


# ---------------------------------------------------------------------------
# The BODY decides before the header: a real document mislabeled text/html
# ---------------------------------------------------------------------------

_VALID_SITEMAP = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    "<url><loc>https://example.com/</loc></url></urlset>"
)


def test_005_valid_sitemap_mislabeled_as_text_html_is_still_a_sitemap():
    """A misconfigured server serving a perfectly valid sitemap with
    `Content-Type: text/html` must not have its document declared absent —
    the body identifies itself, and the header loses."""
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/sitemap.xml":
            return httpx.Response(200, text=_VALID_SITEMAP, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler), ScanOptions(profile="commerce"))
    assert store.get("sitemap_urls")["exists"] is True
    assert store.get("sitemap_urls")["served_as_html"] is False
    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.PASS


def test_005_real_html_soft_404_on_sitemap_is_still_absent():
    """The opposite direction still holds: a `<!doctype html>` body is the
    catch-all page, whatever it claims in its content-type."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        return httpx.Response(
            200, text="<!doctype html><html><body><h1>Not found</h1></body></html>",
            headers={"content-type": "application/xml"},
        )

    store, ctx = _scan(make_client(handler), ScanOptions(profile="commerce"))
    assert store.get("sitemap_urls")["exists"] is False
    assert store.get("sitemap_urls")["served_as_html"] is True
    assert SitemapAvailability().run(store, ctx).status == CheckStatus.FAIL


def test_005_truncated_catch_all_probe_is_absent_at_full_confidence_no_flag():
    """A `/sitemap.xml` probe answered by a catch-all HTML page LARGER than
    the fetch cap must not attach a truncation caveat to the resulting
    "No sitemap was found" finding — that page was never read as sitemap
    content, so its truncation has no bearing on this verdict.

    Regression: `record_truncation` used to run unconditionally before the
    branch dispatch, so this exact case (a served-as-html catch-all bigger
    than the cap, probed on the direct-fetch path when robots.txt declares
    no sitemap) wrote `evidence["truncated"] = True` onto what was otherwise
    a HIGH-confidence, no-note "No sitemap was found." finding — confidence
    and evidence telling two different stories about the same finding."""
    big_html = "<!doctype html><html><body>" + ("x" * 5000) + "</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        # No robots.txt sitemap declared, and /sitemap.xml itself 404s — the
        # DIRECT-PROBE catch-all path this regression lived on.
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text=big_html, headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler, size_limits={"sitemap": 64}), ScanOptions(profile="commerce"))
    record = store.get("sitemap_urls")
    assert record["exists"] is False
    assert record["served_as_html"] is True
    assert record["body_truncated"] is True  # the probe really was cut off — just not evaluated as content

    result = SitemapAvailability().run(store, ctx)
    assert result.status == CheckStatus.FAIL  # commerce profile: a missing sitemap is a real finding
    assert "truncated" not in result.evidence
    assert result.confidence is Confidence.HIGH
    assert "read only in part" not in result.summary


def test_009_llms_txt_mislabeled_as_text_html_is_still_llms_txt():
    llms = "# Site\n\n> summary\n\n## Docs\n- [A](https://example.com/a)\n"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/":
            return httpx.Response(200, content=_DEFAULT_INDEX.encode(), headers={"content-type": "text/html"})
        if path == "/llms.txt":
            return httpx.Response(200, text=llms, headers={"content-type": "text/html"})
        if path == "/a":
            return httpx.Response(200, text="ok", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="not found")

    store, ctx = _scan(make_client(handler))
    assert store.get("llms")["served_as_html"] is False
    assert LlmsTxtIntegrity().run(store, ctx).status == CheckStatus.PASS
